import {ZodError, ZodType} from "zod";

export const validateData = <T>(
  schema: ZodType<T>,
  data: any
): T | ZodError => {
  const result = schema.safeParse(data);

  if (result.success) {
    return result.data;
  } else {
    return result.error;
  }
};
