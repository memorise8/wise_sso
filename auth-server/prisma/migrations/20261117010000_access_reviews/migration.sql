-- 시작 시점의 사용자·역할 정보는 스냅샷으로 보존합니다.
-- 원본 사용자·역할·할당이 삭제돼도 점검 기록은 삭제하지 않습니다.

CREATE TABLE "AccessReview" (
    "id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'OPEN',
    "serviceKeys" JSONB NOT NULL,
    "reasonCode" TEXT NOT NULL,
    "startedById" TEXT NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedById" TEXT,
    "completedAt" TIMESTAMP(3),
    CONSTRAINT "AccessReview_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "AccessReview_status_check"
        CHECK ("status" IN ('OPEN', 'COMPLETED')),
    CONSTRAINT "AccessReview_serviceKeys_check"
        CHECK (jsonb_typeof("serviceKeys") = 'array'),
    CONSTRAINT "AccessReview_completion_check" CHECK (
        ("status" = 'OPEN'
            AND "completedById" IS NULL AND "completedAt" IS NULL)
        OR
        ("status" = 'COMPLETED'
            AND "completedById" IS NOT NULL AND "completedAt" IS NOT NULL)
    )
);

CREATE TABLE "AccessReviewItem" (
    "id" TEXT NOT NULL,
    "reviewId" TEXT NOT NULL,
    "userRoleId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "roleId" TEXT NOT NULL,
    "serviceKey" TEXT NOT NULL,
    "roleName" TEXT NOT NULL,
    "userEmail" TEXT,
    "userName" TEXT,
    "userStatus" TEXT NOT NULL,
    "userType" TEXT,
    "accountExpiresAt" TIMESTAMP(3),
    "decision" TEXT NOT NULL DEFAULT 'PENDING',
    "decidedById" TEXT,
    "decidedAt" TIMESTAMP(3),
    "reasonCode" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AccessReviewItem_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "AccessReviewItem_reviewId_fkey"
        FOREIGN KEY ("reviewId") REFERENCES "AccessReview"("id")
        ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT "AccessReviewItem_decision_check"
        CHECK ("decision" IN ('PENDING', 'KEEP', 'REVOKE', 'ALREADY_REMOVED')),
    CONSTRAINT "AccessReviewItem_decision_fields_check" CHECK (
        ("decision" = 'PENDING'
            AND "decidedById" IS NULL AND "decidedAt" IS NULL
            AND "reasonCode" IS NULL)
        OR
        ("decision" <> 'PENDING'
            AND "decidedById" IS NOT NULL AND "decidedAt" IS NOT NULL
            AND "reasonCode" IS NOT NULL)
    )
);

CREATE INDEX "AccessReview_startedAt_id_idx"
    ON "AccessReview"("startedAt", "id");
CREATE INDEX "AccessReview_status_startedAt_id_idx"
    ON "AccessReview"("status", "startedAt", "id");
CREATE UNIQUE INDEX "AccessReviewItem_reviewId_userRoleId_key"
    ON "AccessReviewItem"("reviewId", "userRoleId");
CREATE INDEX "AccessReviewItem_reviewId_decision_id_idx"
    ON "AccessReviewItem"("reviewId", "decision", "id");
CREATE INDEX "AccessReviewItem_userId_idx"
    ON "AccessReviewItem"("userId");
