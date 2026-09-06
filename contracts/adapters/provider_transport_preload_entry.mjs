import {
  createProviderRecordWriterFromEnvironment,
  installProviderTransport,
  readConfig
} from "./provider_transport_preload.mjs";

const configFile = process.env["WISEACCT_TEST_PROVIDER_CONFIG"];
if (!configFile) {
  throw new TypeError("test-only provider transport: WISEACCT_TEST_PROVIDER_CONFIG is required");
}
const recorder = createProviderRecordWriterFromEnvironment();
installProviderTransport(readConfig(configFile), recorder);
if (recorder) process.once("exit", () => recorder.close());
