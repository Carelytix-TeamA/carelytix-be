import {ZodError, ZodType} from "zod";

export const validateData = <T>(
  data: any,
  schema: ZodType<T>
): T | ZodError => {
  const result = schema.safeParse(data);

  if (result.success) {
    return result.data;
  } else {
    return result.error;
  }
};
