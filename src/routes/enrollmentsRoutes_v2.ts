import { Router, type Request, type Response } from "express";
import { zEnrollmentBody } from "../libs/zodValidators.js";
import { authenticateToken } from "../middlewares/authenMiddleware.js";
import { checkRoleAdmin } from "../middlewares/checkRoleAdminMiddleware.js";
import { checkRoles } from "../middlewares/checkRolesMiddleware.js";

import {
  enrollments,
  students,
  courses,
  reset_enrollments,
} from "../db/db.js";

import type { Enrollment } from "../libs/types.js";
import type { CustomRequest } from "../libs/types.js";

const router = Router();

function aggregateEnrollments() {
  const map: Record<string, string[]> = {};
  enrollments.forEach((e) => {
    if (!map[e.studentId]) {
    map[e.studentId] = [];
    }
    const studentCourses = map[e.studentId]!;
    if (!studentCourses.includes(e.courseId)) {
    studentCourses.push(e.courseId);
    }
  });
  return Object.keys(map).map((sid) => ({
    studentId: sid,
    courses: map[sid],
  }));
}

router.get("/", authenticateToken, checkRoleAdmin, (req: Request, res: Response) => {
  return res.status(200).json({
    success: true,
    message: "Enrollments Information",
    data: aggregateEnrollments(),
  });
});

router.post("/reset", authenticateToken, checkRoleAdmin, (req: Request, res: Response) => {
  try {
    reset_enrollments();
    return res.status(200).json({
      success: true,
      message: "enrollments database has been reset",
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});

router.get(
  "/:studentId",
  authenticateToken,
  checkRoles,
  (req: CustomRequest, res: Response) => {
    try {
      const sid = req.params.studentId;

      const payload = req.user;
      if (payload?.role === "STUDENT" && payload.studentId !== sid) {
        return res.status(403).json({
          success: false,
          message: "Forbidden access",
        });
      }

      const studentEnrolls = enrollments
        .filter((e) => e.studentId === sid)
        .map((e) => e.courseId);

      return res.status(200).json({
        success: true,
        message: "Student Information",
        data: {
          studentId: sid,
          courses: studentEnrolls,
        },
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        message: "Something is wrong, please try again",
        error: err,
      });
    }
  }
);

router.post("/:studentId", authenticateToken, checkRoles, (req: CustomRequest, res: Response) => {
  try {
    const sid = req.params.studentId;
    const payload = req.user;

    if (payload?.role !== "STUDENT" || payload.studentId !== sid) {
      return res.status(403).json({
        success: false,
        message: "You are not allowed to modify another student's data",
      });
    }

    const parse = zEnrollmentBody.safeParse({ studentId: sid, ...req.body });
    if (!parse.success) {
      return res.status(400).json({
        success: false,
        message: "Validation failed",
        errors: parse.error.issues[0]?.message,
      });
    }

    const { courseId } = parse.data;

    const courseExists = courses.find((c) => c.courseId === courseId);
    if (!courseExists) {
      return res.status(404).json({
        success: false,
        message: "Course does not exists",
      });
    }

    const exists = enrollments.find((e) => e.studentId === sid && e.courseId === courseId);
    if (exists) {
      return res.status(409).json({
        success: false,
        message: "studentId && courseId is already exists",
      });
    }

    const newEnroll: Enrollment = {
      studentId: sid,
      courseId,
    };
    enrollments.push(newEnroll);

    return res.status(201).json({
      success: true,
      message: `Student ${sid} && Course ${courseId} has been added successfully`,
      data: newEnroll,
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});

router.delete("/:studentId", authenticateToken, checkRoles, (req: CustomRequest, res: Response) => {
  try {
    const sid = req.params.studentId;
    const payload = req.user;

    if (payload?.role !== "STUDENT" || !payload.studentId || payload.studentId !== sid) {
    return res.status(403).json({
        success: false,
        message: "You are not allowed to modify another student's data",
    });
    }

    const parse = zEnrollmentBody.safeParse({ studentId: sid, ...req.body });
    if (!parse.success) {
      return res.status(400).json({
        success: false,
        message: "Validation failed",
        errors: parse.error.issues[0]?.message,
      });
    }

    const { courseId } = parse.data;

    const foundIndex = enrollments.findIndex((e) => e.studentId === sid && e.courseId === courseId);
    if (foundIndex === -1) {
      return res.status(404).json({
        success: false,
        message: "Enrollment does not exists",
      });
    }

    enrollments.splice(foundIndex, 1);

    return res.status(200).json({
      success: true,
      message: `Student ${sid} && Course ${courseId} has been deleted successfully`,
      data: aggregateEnrollments(),
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});

export default router;
