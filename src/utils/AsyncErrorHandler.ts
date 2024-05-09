import exp from 'constants';
import { RequestHandler, Request, Response, NextFunction } from 'express';

type AsyncHandlerFunction = (
  req: Request,
  res: Response,
  next: NextFunction,
) => Promise<any>;

const AsyncErrorHandler = (fn: AsyncHandlerFunction) => {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res, next).catch((err: Error) => next(err));
  };
};

export default AsyncErrorHandler;
