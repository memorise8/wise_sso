-- 접근 정책만 저장하며 비밀값·리다이렉트 주소는 저장하지 않습니다.
-- 요청자와 다른 한 명의 관리자가 승인 또는 거절합니다.

CREATE TABLE "OidcAccessPolicy" (
    "clientId" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "policy" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "updatedById" TEXT,
    "updatedByEmail" TEXT,
    CONSTRAINT "OidcAccessPolicy_pkey" PRIMARY KEY ("clientId"),
    CONSTRAINT "OidcAccessPolicy_version_check" CHECK ("version" >= 1),
    CONSTRAINT "OidcAccessPolicy_policy_check" CHECK (jsonb_typeof("policy") = 'object' AND "policy" ?& ARRAY['allowedUserTypes', 'requiredRoles', 'allowWithoutRequiredRole', 'groupsServiceKeys', 'ssoAutoLogin'] AND ("policy" - ARRAY['allowedUserTypes', 'requiredRoles', 'allowWithoutRequiredRole', 'groupsServiceKeys', 'ssoAutoLogin']) = '{}'::jsonb)
);

CREATE TABLE "OidcPolicyChange" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "baseVersion" INTEGER NOT NULL,
    "appliedVersion" INTEGER,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "beforePolicy" JSONB NOT NULL,
    "proposedPolicy" JSONB NOT NULL,
    "requestedById" TEXT NOT NULL,
    "requestedByEmail" TEXT,
    "requestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "reasonCode" TEXT NOT NULL,
    "rollbackToVersion" INTEGER,
    "resolvedAt" TIMESTAMP(3),
    CONSTRAINT "OidcPolicyChange_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "OidcPolicyChange_baseVersion_check" CHECK ("baseVersion" >= 1),
    CONSTRAINT "OidcPolicyChange_beforePolicy_check" CHECK (jsonb_typeof("beforePolicy") = 'object' AND "beforePolicy" ?& ARRAY['allowedUserTypes', 'requiredRoles', 'allowWithoutRequiredRole', 'groupsServiceKeys', 'ssoAutoLogin'] AND ("beforePolicy" - ARRAY['allowedUserTypes', 'requiredRoles', 'allowWithoutRequiredRole', 'groupsServiceKeys', 'ssoAutoLogin']) = '{}'::jsonb),
    CONSTRAINT "OidcPolicyChange_proposedPolicy_check" CHECK (jsonb_typeof("proposedPolicy") = 'object' AND "proposedPolicy" ?& ARRAY['allowedUserTypes', 'requiredRoles', 'allowWithoutRequiredRole', 'groupsServiceKeys', 'ssoAutoLogin'] AND ("proposedPolicy" - ARRAY['allowedUserTypes', 'requiredRoles', 'allowWithoutRequiredRole', 'groupsServiceKeys', 'ssoAutoLogin']) = '{}'::jsonb),
    CONSTRAINT "OidcPolicyChange_state_check" CHECK (("status" = 'PENDING' AND "appliedVersion" IS NULL AND "resolvedAt" IS NULL)
            OR ("status" = 'APPLIED' AND "appliedVersion" IS NOT NULL AND "appliedVersion" = "baseVersion" + 1
                AND "resolvedAt" IS NOT NULL)
            OR ("status" = 'REJECTED' AND "appliedVersion" IS NULL
                AND "resolvedAt" IS NOT NULL)),
    CONSTRAINT "OidcPolicyChange_rollback_check" CHECK ("rollbackToVersion" IS NULL OR ("rollbackToVersion" >= 1 AND "rollbackToVersion" < "baseVersion")),
    CONSTRAINT "OidcPolicyChange_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "OidcAccessPolicy"("clientId") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "OidcPolicyChange_id_requestedById_key" ON "OidcPolicyChange"("id", "requestedById");

CREATE UNIQUE INDEX "OidcPolicyChange_clientId_appliedVersion_key" ON "OidcPolicyChange"("clientId", "appliedVersion");

CREATE INDEX "OidcPolicyChange_clientId_requestedAt_id_idx" ON "OidcPolicyChange"("clientId", "requestedAt", "id");

CREATE INDEX "OidcPolicyChange_status_requestedAt_id_idx" ON "OidcPolicyChange"("status", "requestedAt", "id");

CREATE TABLE "OidcPolicyDecision" (
    "id" TEXT NOT NULL,
    "requestId" TEXT NOT NULL,
    "requestedById" TEXT NOT NULL,
    "decision" TEXT NOT NULL,
    "decidedById" TEXT NOT NULL,
    "decidedByEmail" TEXT,
    "decidedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "reasonCode" TEXT NOT NULL,
    CONSTRAINT "OidcPolicyDecision_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "OidcPolicyDecision_decision_check" CHECK ("decision" IN ('APPROVE', 'REJECT')),
    CONSTRAINT "OidcPolicyDecision_two_person_check" CHECK ("requestedById" <> "decidedById"),
    CONSTRAINT "OidcPolicyDecision_requestId_requestedById_fkey" FOREIGN KEY ("requestId", "requestedById") REFERENCES "OidcPolicyChange"("id", "requestedById") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "OidcPolicyDecision_requestId_key" ON "OidcPolicyDecision"("requestId");

CREATE UNIQUE INDEX "OidcPolicyDecision_requestId_requestedById_key" ON "OidcPolicyDecision"("requestId", "requestedById");

CREATE INDEX "OidcPolicyDecision_decidedById_decidedAt_idx" ON "OidcPolicyDecision"("decidedById", "decidedAt");
