# frozen_string_literal: true

# This helper runs inside the pinned GitLab CE image. The runner supplies only
# synthetic FastAPI-produced OIDC material on stdin. Faraday's test adapter
# intercepts network I/O, while the packaged GitLab OIDC gems still construct
# and authenticate each request and verify every ID token.

require 'base64'
require 'digest'
require 'json'
require 'rack/mock'
require 'stringio'
require 'uri'
require 'omniauth_openid_connect'

def assert(condition, message)
  raise "probe assertion failed: #{message}" unless condition
end

def assert_rejected(message, expected_class)
  begin
    yield
  rescue Exception => error # rubocop:disable Lint/RescueException
    assert(error.class.name == expected_class, "#{message} raised #{error.class.name}")
    return
  end
  raise "probe assertion failed: #{message} was accepted"
end

fixture = JSON.parse($stdin.read)
required_fixture_keys = %w[
  access_token client_id client_secret id_tokens issuer jwks nonce redirect_uri userinfo
]
assert(fixture.keys.sort == required_fixture_keys.sort, 'unexpected fixture shape')

expected_versions = {
  'omniauth_openid_connect' => '0.8.0',
  'openid_connect' => '2.3.1',
  'rack-oauth2' => '2.2.1'
}.freeze
expected_versions.each do |name, version|
  loaded = Gem.loaded_specs.fetch(name).version.to_s
  assert(loaded == version, "unexpected #{name} version #{loaded}")
end

manifest = File.read('/opt/gitlab/version-manifest.txt')
assert(manifest.lines.first&.strip == 'gitlab-ce 19.4.1', 'unexpected GitLab version')

requests = []
jwks_requests = []
userinfo_response = fixture.fetch('userinfo')
token_response = {
  'access_token' => fixture.fetch('access_token'),
  'token_type' => 'Bearer',
  'expires_in' => 300,
  'id_token' => fixture.fetch('id_tokens').fetch('valid')
}

# The only monkeypatch is the transport factory: a Faraday test adapter makes
# network access impossible and captures the final request after the real gem
# middleware has applied Basic/Bearer authentication and form encoding.
Rack::OAuth2.singleton_class.send(:define_method, :http_client) do |*_args, &configuration|
  Faraday.new do |faraday|
    faraday.request :url_encoded
    faraday.response :json
    configuration&.call(faraday)
    faraday.adapter :test do |stub|
      stub.post('/oauth2/token') do |environment|
        requests << {
          kind: 'token',
          url: environment.url.to_s,
          authorization: environment.request_headers['Authorization'],
          form: URI.decode_www_form(environment.body.to_s).to_h
        }
        [200, { 'Content-Type' => 'application/json' }, JSON.generate(token_response)]
      end
      stub.get('/oauth2/userinfo') do |environment|
        requests << {
          kind: 'userinfo',
          url: environment.url.to_s,
          authorization: environment.request_headers['Authorization']
        }
        [200, { 'Content-Type' => 'application/json' }, JSON.generate(userinfo_response)]
      end
    end
  end
end

oidc_http_response = Struct.new(:body)
oidc_http_client = Object.new
oidc_http_client.define_singleton_method(:get) do |url|
  jwks_requests << url
  oidc_http_response.new(JSON.generate(fixture.fetch('jwks')))
end
OpenIDConnect.singleton_class.send(:define_method, :http_client) { oidc_http_client }

issuer = fixture.fetch('issuer').delete_suffix('/')
jwks_uri = "#{issuer}/.well-known/jwks.json"
client_options = {
  identifier: fixture.fetch('client_id'),
  secret: fixture.fetch('client_secret'),
  authorization_endpoint: "#{issuer}/oauth2/authorize",
  token_endpoint: "#{issuer}/oauth2/token",
  userinfo_endpoint: "#{issuer}/oauth2/userinfo",
  jwks_uri: jwks_uri,
  redirect_uri: fixture.fetch('redirect_uri')
}.freeze

strategy = OmniAuth::Strategies::OpenIDConnect.new(
  ->(_environment) { [200, {}, []] },
  issuer: fixture.fetch('issuer'),
  discovery: false,
  scope: %w[openid profile email],
  response_type: 'code',
  send_nonce: true,
  send_scope_to_token_endpoint: false,
  client_auth_method: 'basic',
  client_signing_alg: 'RS256',
  pkce: true,
  client_options: client_options
)
environment = Rack::MockRequest.env_for(
  'https://gitlab.example.invalid/users/auth/openid_connect',
  'rack.session' => {},
  'rack.session.options' => {}
)
strategy.instance_variable_set(:@env, environment)
authorize_uri = URI(strategy.send(:authorize_uri))
authorize_query = URI.decode_www_form(authorize_uri.query).to_h
session = environment.fetch('rack.session')
verifier = session.fetch('omniauth.pkce.verifier')
nonce = session.fetch('omniauth.nonce')
challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false)

assert(verifier.length == 128, 'GitLab PKCE verifier must be 128 characters')
assert(authorize_query.fetch('code_challenge') == challenge, 'PKCE challenge mismatch')
assert(authorize_query.fetch('code_challenge_method') == 'S256', 'PKCE method mismatch')
assert(authorize_query.fetch('nonce') == nonce, 'nonce was not persisted in the session')
assert(authorize_query.fetch('scope') == 'openid profile email', 'authorize scope mismatch')
assert(authorize_query.fetch('redirect_uri') == fixture.fetch('redirect_uri'), 'redirect mismatch')
assert(authorize_uri.to_s.start_with?("#{issuer}/oauth2/authorize?"), 'authorize URL mismatch')

def exchange(client_options, method, verifier)
  client = OpenIDConnect::Client.new(client_options)
  client.authorization_code = 'synthetic-authorization-code'
  client.access_token!(scope: nil, client_auth_method: method, code_verifier: verifier)
end

basic_token = exchange(client_options, :basic, verifier)
post_token = exchange(client_options, :query, verifier)
token_requests = requests.select { |request| request.fetch(:kind) == 'token' }
assert(token_requests.length == 2, 'expected two token requests')

basic_request, post_request = token_requests
assert(basic_request.fetch(:authorization).to_s.start_with?('Basic '), 'Basic auth missing')
assert(!basic_request.fetch(:form).key?('client_id'), 'Basic request leaked client_id into body')
assert(!basic_request.fetch(:form).key?('client_secret'), 'Basic request leaked secret into body')
assert(post_request.fetch(:authorization).nil?, 'post-auth request unexpectedly used a header')
assert(post_request.fetch(:form).fetch('client_id') == fixture.fetch('client_id'), 'post client mismatch')
assert(post_request.fetch(:form).fetch('client_secret') == fixture.fetch('client_secret'), 'post secret mismatch')
token_requests.each do |request|
  form = request.fetch(:form)
  assert(request.fetch(:url) == "#{issuer}/oauth2/token", 'token URL mismatch')
  assert(form.fetch('grant_type') == 'authorization_code', 'grant type mismatch')
  assert(form.fetch('redirect_uri') == fixture.fetch('redirect_uri'), 'token redirect mismatch')
  assert(form.fetch('code_verifier') == verifier, 'token PKCE verifier mismatch')
  assert(!form.key?('scope'), 'scope must be omitted when configured false')
end

userinfo = basic_token.userinfo!
userinfo_request = requests.find { |request| request.fetch(:kind) == 'userinfo' }
assert(userinfo_request, 'UserInfo request missing')
assert(userinfo_request.fetch(:url) == "#{issuer}/oauth2/userinfo", 'UserInfo URL mismatch')
assert(userinfo_request.fetch(:authorization).to_s.start_with?('Bearer '), 'Bearer auth missing')
assert(userinfo.raw_attributes.fetch('sub') == fixture.fetch('userinfo').fetch('sub'), 'UserInfo sub mismatch')

def decoded_token(strategy, compact_token)
  strategy.send(:decode_id_token, compact_token)
end

valid = decoded_token(strategy, fixture.fetch('id_tokens').fetch('valid'))
valid.verify!(
  issuer: fixture.fetch('issuer'),
  client_id: fixture.fetch('client_id'),
  nonce: fixture.fetch('nonce')
)
assert(jwks_requests == [jwks_uri], 'JWKS was not fetched from the configured absolute URL')

assert_rejected('bad signature', 'JSON::JWS::VerificationFailed') do
  decoded_token(strategy, fixture.fetch('id_tokens').fetch('bad_signature'))
end
{
  'wrong_audience' => 'OpenIDConnect::ResponseObject::IdToken::InvalidAudience',
  'wrong_issuer' => 'OpenIDConnect::ResponseObject::IdToken::InvalidIssuer',
  'wrong_nonce' => 'OpenIDConnect::ResponseObject::IdToken::InvalidNonce',
  'expired' => 'OpenIDConnect::ResponseObject::IdToken::ExpiredToken'
}.each do |name, expected_class|
  assert_rejected(name.tr('_', ' '), expected_class) do
    decoded_token(strategy, fixture.fetch('id_tokens').fetch(name)).verify!(
      issuer: fixture.fetch('issuer'),
      client_id: fixture.fetch('client_id'),
      nonce: fixture.fetch('nonce')
    )
  end
end

# omniauth_openid_connect 0.8.0 does not explicitly reject a UserInfo `sub`
# mismatch. It merges the already-verified ID token after UserInfo, so the ID
# token `sub` wins. Wise SSO must therefore keep both endpoint subjects equal.
userinfo_response = fixture.fetch('userinfo').merge('sub' => 'mismatched-userinfo-sub')
mismatch_strategy = OmniAuth::Strategies::OpenIDConnect.new(
  ->(_environment) { [200, {}, []] },
  issuer: fixture.fetch('issuer'),
  discovery: false,
  client_signing_alg: 'RS256',
  client_options: client_options
)
mismatch_strategy.instance_variable_set(:@access_token, post_token)
merged = mismatch_strategy.send(:user_info)
id_token_subject = valid.raw_attributes.fetch('sub')
assert(merged.raw_attributes.fetch('sub') == id_token_subject, 'ID-token sub did not win merge')
assert(jwks_requests == [jwks_uri, jwks_uri], 'mismatch path did not use configured JWKS URL')

puts JSON.generate(
  status: 'pass',
  gitlab: '19.4.1',
  gems: expected_versions,
  checks: {
    authorize_nonce: true,
    pkce_s256: true,
    pkce_verifier_length: verifier.length,
    token_basic: true,
    token_post_form: true,
    token_scope_omitted: true,
    userinfo_bearer: true,
    absolute_endpoints: true,
    jwks_uri_fetch: true,
    rs256_id_token: true,
    negative_signature_audience_issuer_nonce_expiry: true,
    userinfo_sub_mismatch_explicitly_rejected: false,
    userinfo_effective_sub_source: 'verified_id_token'
  }
)
