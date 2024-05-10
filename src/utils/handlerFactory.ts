import { Request, Response, NextFunction } from 'express';
import { Model, Models } from 'mongoose';

import AsyncErrorHandler from './AsyncErrorHandler';
import AppError from './AppError';

const getCollectionName = (Model: Model<any>) =>
  Model.collection.collectionName;

export const deleteOne = (Model: Model<any>) =>
  AsyncErrorHandler(async (req: Request, res: Response, next: NextFunction) => {
    const doc = await Model.findByIdAndDelete(req.params.id);

    if (!doc) {
      return next(new AppError(`No document found with that id`, 404));
    }
    res.status(204).json({
      status: 'success',
      data: null,
    });
  });

export const updateOne = (Model: Model<any>) =>
  AsyncErrorHandler(async (req: Request, res: Response, next: NextFunction) => {
    const doc = await Model.findByIdAndUpdate(req.params.id, req.body, {
      new: true, // will return new updated document
      runValidators: true, // validators specified in schemas will be run again
    });

    if (!doc) {
      return next(new AppError('No document found with that id', 404));
    }
    res.status(200).json({
      status: 'success',
      data: {
        doc,
      },
    });
  });

export const createOne = (Model: Model<any>) =>
  AsyncErrorHandler(async (req: Request, res: Response, next: NextFunction) => {
    const doc = await Model.create(req.body);
    res.status(201).json({
      status: 'success',
      data: {
        doc,
      },
    });
  });

export const getOne = (Model: Model<any>, populateOpts?: string[]) =>
  AsyncErrorHandler(async (req: Request, res: Response, next: NextFunction) => {
    let query = Model.findById(req.params.id);

    if (populateOpts) {
      populateOpts.forEach((opt) => (query = query.populate(opt)));
    }
    const doc = await query;

    if (!doc) {
      return next(new AppError('No document found with that id', 404));
    }
    res.status(200).json({
      status: 'success',
      data: {
        data: doc,
      },
    });
  });

export const getAll = (Model: Model<any>) =>
  AsyncErrorHandler(async (_req: Request, res: Response, _next: NextFunction) => {
    const docs = await Model.find();

    res.status(200).json({
      status: 'success',
      results: docs.length,
      data: {
        [getCollectionName(Model)]: docs,
      },
    });
  });
