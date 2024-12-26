import prisma from '../DB/dbConfig.js';

const deleteExpiredOtps = async () => {
  const now = new Date();
  await prisma.otp.deleteMany({
    where: {
      expiresAt: {
        lt: now,
      },
    },
  });
};

export default deleteExpiredOtps;