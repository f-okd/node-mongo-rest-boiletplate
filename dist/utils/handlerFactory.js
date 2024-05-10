"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getAll = exports.getOne = exports.createOne = exports.updateOne = exports.deleteOne = void 0;
const AsyncErrorHandler_1 = __importDefault(require("./AsyncErrorHandler"));
const AppError_1 = __importDefault(require("./AppError"));
const getCollectionName = (Model) => Model.collection.collectionName;
const deleteOne = (Model) => (0, AsyncErrorHandler_1.default)((req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const doc = yield Model.findByIdAndDelete(req.params.id);
    if (!doc) {
        return next(new AppError_1.default(`No document found with that id`, 404));
    }
    res.status(204).json({
        status: 'success',
        data: null,
    });
}));
exports.deleteOne = deleteOne;
const updateOne = (Model) => (0, AsyncErrorHandler_1.default)((req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const doc = yield Model.findByIdAndUpdate(req.params.id, req.body, {
        new: true, // will return new updated document
        runValidators: true, // validators specified in schemas will be run again
    });
    if (!doc) {
        return next(new AppError_1.default('No document found with that id', 404));
    }
    res.status(200).json({
        status: 'success',
        data: {
            doc,
        },
    });
}));
exports.updateOne = updateOne;
const createOne = (Model) => (0, AsyncErrorHandler_1.default)((req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const doc = yield Model.create(req.body);
    res.status(201).json({
        status: 'success',
        data: {
            doc,
        },
    });
}));
exports.createOne = createOne;
const getOne = (Model, populateOpts) => (0, AsyncErrorHandler_1.default)((req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    let query = Model.findById(req.params.id);
    if (populateOpts) {
        populateOpts.forEach((opt) => (query = query.populate(opt)));
    }
    const doc = yield query;
    if (!doc) {
        return next(new AppError_1.default('No document found with that id', 404));
    }
    res.status(200).json({
        status: 'success',
        data: {
            data: doc,
        },
    });
}));
exports.getOne = getOne;
const getAll = (Model) => (0, AsyncErrorHandler_1.default)((req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    const docs = yield Model.find();
    res.status(200).json({
        status: 'success',
        results: docs.length,
        data: {
            [getCollectionName(Model)]: docs,
        },
    });
}));
exports.getAll = getAll;
