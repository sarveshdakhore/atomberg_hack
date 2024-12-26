import prisma from "../DB/dbConfig.js";

export const collectAndSaveData = async (req, res) => {
  try {
    console.log(req.body.tanks);

    if (!Array.isArray(req.body.tanks)) {
      return res.status(400).json({ error: "Invalid payload format" });
    }

    for (const tankData of req.body.tanks) {
      const { tankId, fluidLevels, waterQuality } = tankData;

      // Check if the user has the specified tank
      const tank = await prisma.tank.findUnique({
        where: { id: tankId },
        include: { user: true }
      });

      if (!tank) {
        throw new Error(`Tank with ID ${tankId} not found for the user.`);
      }

      // Save fluid level data
      await prisma.fluidLevel.create({
        data: {
          levels: fluidLevels.map(fl => fl.level),
          timestamps: fluidLevels.map(fl => new Date(fl.timestamp)),
          tankId: tankId
        }
      });

      // Save water quality data
      await prisma.waterQuality.create({
        data: {
          pH: waterQuality.pH,
          turbidity: waterQuality.turbidity,
          temperature: waterQuality.temperature,
          tds: waterQuality.tds,
          timestamp: new Date(waterQuality.timestamp),
          tankId: tankId
        }
      });
    }

    res.status(200).json({ message: "Data saved successfully" });
  } catch (error) {
    console.error("Error saving data:", error);
    res.status(500).json({ error: error.message });
  }
};