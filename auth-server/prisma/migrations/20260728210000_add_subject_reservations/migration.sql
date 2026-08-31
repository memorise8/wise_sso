CREATE TABLE "SubjectReservation" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "subjectId" TEXT NOT NULL,
    "reason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SubjectReservation_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "SubjectReservation_email_key" ON "SubjectReservation"("email");
CREATE UNIQUE INDEX "SubjectReservation_subjectId_key" ON "SubjectReservation"("subjectId");
