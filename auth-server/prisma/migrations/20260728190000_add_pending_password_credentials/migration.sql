CREATE TABLE "PendingPasswordCredential" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PendingPasswordCredential_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "PendingPasswordCredential_userId_key" ON "PendingPasswordCredential"("userId");
CREATE UNIQUE INDEX "PendingPasswordCredential_email_key" ON "PendingPasswordCredential"("email");
CREATE INDEX "PendingPasswordCredential_expiresAt_idx" ON "PendingPasswordCredential"("expiresAt");

ALTER TABLE "PendingPasswordCredential"
ADD CONSTRAINT "PendingPasswordCredential_userId_fkey"
FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
