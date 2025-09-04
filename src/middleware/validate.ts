import { NextFunction, Request, Response } from 'express';
import { ZodSchema } from 'zod';

export function validateBody(schema: ZodSchema) {
    return (req: Request, res: Response, next: NextFunction) => {
        const result = schema.safeParse(req.body);
        if (!result.success) {
            return res.status(400).json({
                error: {
                    code: 'VALIDATION_ERROR',
                    message: 'Invalid request body',
                    details: result.error.flatten(),
                },
            });
        }
        // assign parsed data back
        req.body = result.data;
        next();
    };
}
