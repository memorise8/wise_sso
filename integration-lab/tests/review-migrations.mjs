// In-memory WASM PostgreSQL validation only. Never opens a production connection.
// PGLITE_MODULE_PATH=/tmp/review-pg/node_modules/@electric-sql/pglite/dist/index.js node integration-lab/tests/review-migrations.mjs
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
const { PGlite } = await import(pathToFileURL(process.env.PGLITE_MODULE_PATH).href);
const root = process.cwd();
const base = path.join(root, 'auth-server/prisma/migrations');
const names = fs.readdirSync(base).filter(n => fs.existsSync(path.join(base, n, 'migration.sql'))).sort();
const read = name => fs.readFileSync(path.join(base, name, 'migration.sql'), 'utf8');
const policy = '20261102000000_user_types_and_sso_admin';
const session = '20261102010000_central_sso_sessions';
const invitations = '20261104000000_employee_invitations';
const restore = '20261104010000_restore_legacy_admin_grants';
for (const oldDraft of [false, true]) {
  const pg = new PGlite();
  for (const name of names.filter(n => n < policy)) await pg.exec(read(name));
  await pg.exec(`INSERT INTO "User" (id,email,status,"emailVerified","updatedAt") VALUES ('legacy-admin','legacy@example.invalid','ACTIVE',true,now());
    INSERT INTO "Role" (id,"serviceKey",name) VALUES ('old-admin','temis','admin');
    INSERT INTO "UserRole" (id,"userId","roleId") VALUES ('old-grant','legacy-admin','old-admin');`);
  await pg.exec(fs.readFileSync("fastapi-auth-server/ops/user-types/preview.sql", "utf8"));
  await pg.exec(oldDraft ? execFileSync('git', ['show', '2b65126:auth-server/prisma/migrations/' + policy + '/migration.sql'], {encoding:'utf8'}) : read(policy));
  if (!oldDraft) {
    assert.equal((await pg.query(`SELECT count(*) AS n FROM "UserRole" WHERE "roleId"='old-admin'`)).rows[0].n, 1);
    assert.equal((await pg.query(`SELECT count(*) AS n FROM "AuditLog" WHERE "userId" IS NOT NULL`)).rows[0].n, 0);
  }
  await pg.exec(read(session));
  await pg.exec(read(invitations));
  await pg.exec(read(restore));
  assert.equal((await pg.query(`SELECT count(*) AS n FROM "UserRole" WHERE "roleId"='old-admin'`)).rows[0].n, 1);
  await pg.exec(`INSERT INTO "User" (id,email,"userType","updatedAt") VALUES
    ('employee','employee@example.invalid',NULL,now()),('customer','customer@example.invalid',NULL,now()),
    ('empty','empty@example.invalid',NULL,now()),('typed','typed@example.invalid','CUSTOMER',now());
    INSERT INTO "Role" (id,"serviceKey",name) VALUES ('maintainer','gitlab','maintainer'),('customer-role','temis','user');
    INSERT INTO "UserRole" (id,"userId","roleId") VALUES ('r1','employee','maintainer'),('r2','customer','customer-role'),('r3','typed','maintainer');`);
  const before = (await pg.query(`SELECT * FROM "User" ORDER BY id`)).rows;
  await pg.exec(fs.readFileSync('fastapi-auth-server/ops/user-types/preview.sql','utf8'));
  assert.deepEqual((await pg.query(`SELECT * FROM "User" ORDER BY id`)).rows, before);
  await pg.exec(fs.readFileSync('fastapi-auth-server/ops/user-types/apply.sql','utf8'));
  const users = (await pg.query(`SELECT id,"userType","ssoSessionVersion" AS version FROM "User" WHERE id IN ('employee','customer','empty','typed') ORDER BY id`)).rows;
  assert.deepEqual(users.map(x => [x.id,x.userType,x.version]), [['customer','CUSTOMER',1],['employee','EMPLOYEE',1],['empty','CUSTOMER',1],['typed','CUSTOMER',0]]);
  const audits = (await pg.query(`SELECT count(*) AS n FROM "AuditLog" WHERE "reasonCode"='OPERATOR_USER_TYPE_BACKFILL'`)).rows[0].n;
  await pg.exec(fs.readFileSync('fastapi-auth-server/ops/user-types/apply.sql','utf8'));
  assert.equal((await pg.query(`SELECT count(*) AS n FROM "AuditLog" WHERE "reasonCode"='OPERATOR_USER_TYPE_BACKFILL'`)).rows[0].n, audits);
  if (process.env.INVITATION_SQL_PATH) {
    await pg.exec(`INSERT INTO "User" (id,email,"userType",status,"emailVerified","updatedAt") VALUES ('admin','actor@example.invalid','EMPLOYEE','ACTIVE',true,now());`);
    const statements = JSON.parse(fs.readFileSync(process.env.INVITATION_SQL_PATH, 'utf8'));
    for (const statement of statements) await pg.query(statement.sql, statement.params);
    const invited = (await pg.query(`SELECT "userType",status,"emailVerified" FROM "User" WHERE email='real-sql@example.test'`)).rows[0];
    assert.deepEqual(invited, {userType:'EMPLOYEE',status:'ACTIVE',emailVerified:true});
    assert.equal((await pg.query(`SELECT count(*) AS n FROM "EmployeeInvitation" WHERE status='ACCEPTED'`)).rows[0].n, 1);
  }
  console.log('PASS:', oldDraft ? 'old applied draft + compensating migration' : 'fresh additive migration', '+ read-only preview + idempotent user classification');
  await pg.close();
}
