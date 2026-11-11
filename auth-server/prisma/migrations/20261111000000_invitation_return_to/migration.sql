-- Where a service-issued invitation sends the person after they set a password.
ALTER TABLE "EmployeeInvitation" ADD COLUMN "returnTo" TEXT;
