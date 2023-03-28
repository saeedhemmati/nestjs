/*
  Warnings:

  - You are about to drop the column `lastNAme` on the `User` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "User" DROP COLUMN "lastNAme",
ADD COLUMN     "lastName" TEXT;
