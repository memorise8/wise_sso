ALTER TABLE "EmailVerificationToken"
  ADD COLUMN "handoffClientId" TEXT,
  ADD COLUMN "handoffAudience" TEXT,
  ADD COLUMN "handoffRedirectUri" TEXT,
  ADD COLUMN "handoffState" TEXT,
  ADD COLUMN "handoffCodeChallenge" TEXT,
  ADD COLUMN "handoffCodeChallengeMethod" TEXT;
