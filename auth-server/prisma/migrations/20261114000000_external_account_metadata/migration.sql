ALTER TABLE "User"
    ADD COLUMN "externalInvitedById" TEXT,
    ADD COLUMN "externalCompany" TEXT,
    ADD COLUMN "externalProject" TEXT;

ALTER TABLE "EmployeeInvitation"
    ADD COLUMN "externalInvitedById" TEXT;
