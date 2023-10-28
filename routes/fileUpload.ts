/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import os from 'os'
import fs = require('fs')
import challengeUtils = require('../lib/challengeUtils')
import { type NextFunction, type Request, type Response } from 'express'
import path from 'path'
import * as utils from '../lib/utils'

const challenges = require('../data/datacache').challenges
const libxml = require('libxmljs2')
const vm = require('vm')
const unzipper = require('unzipper')

function ensureFileIsPassed ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    next()
  }
}

function handleZipFileUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.zip')) {
    if (((file?.buffer) != null) && !utils.disableOnContainerEnv()) {
      const buffer = file.buffer
      const filename = file.originalname.toLowerCase()
      const tempFile = path.join(os.tmpdir(), filename)
      fs.open(tempFile, 'w', function (err, fd) {
        if (err != null) { next(err) }
        fs.write(fd, buffer, 0, buffer.length, null, function (err) {
          if (err != null) { next(err) }
          fs.close(fd, function () {
            fs.createReadStream(tempFile)
              .pipe(unzipper.Parse())
              .on('entry', function (entry: any) {
                const fileName = entry.path
                const absolutePath = path.resolve('uploads/complaints/' + fileName)
                challengeUtils.solveIf(challenges.fileWriteChallenge, () => { return absolutePath === path.resolve('ftp/legal.md') })
                if (absolutePath.includes(path.resolve('.'))) {
                  entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName).on('error', function (err) { next(err) }))
                } else {
                  entry.autodrain()
                }
              }).on('error', function (err: unknown) { next(err) })
          })
        })
      })
    }
    res.status(204).end()
  } else {
    next()
  }
}

function checkUploadSize ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    challengeUtils.solveIf(challenges.uploadSizeChallenge, () => { return file?.size > 100000 })
  }
  next()
}

function checkFileType ({ file }: Request, res: Response, next: NextFunction) {
  const fileType = file?.originalname.substr(file.originalname.lastIndexOf('.') + 1).toLowerCase()
  challengeUtils.solveIf(challenges.uploadTypeChallenge, () => {
    return !(fileType === 'pdf' || fileType === 'xml' || fileType === 'zip')
  })
  next()
}


function handleXmlUpload({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.xml')) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    
    // Check if file.buffer is defined
    if (file?.buffer != null) {
      const data = file.buffer.toString();
      try {
        const sandbox = { libxml, data };
        vm.createContext(sandbox);

        // Add the strict option to the parser constructor and set it to false
        const xmlDoc = vm.runInContext('libxml.parseXml(data, { strict: false, noblanks: true, noent: true, nocdata: true, xxe: false })', sandbox, { timeout: 2000 });

        const xmlString = xmlDoc.toString(false);
        
        // If it contains entity prevent the attack. 
        if (xmlString.includes('ENTITY')) {
          res.status(400); 
          next(new Error('XML content contains forbidden string "ENTITY" (' + file.originalname + ')'));
          return;
        }

        challengeUtils.solveIf(challenges.xxeFileDisclosureChallenge, () => { return (utils.matchesEtcPasswdFile(xmlString) || utils.matchesSystemIniFile(xmlString)) });

        res.status(410);
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(xmlString, 400) + ' (' + file.originalname + ')'));
      } catch (err: any) { // TODO: Remove any
        if (utils.contains(err.message, 'Script execution timed out')) {
          if (challengeUtils.notSolved(challenges.xxeDosChallenge)) {
            challengeUtils.solve(challenges.xxeDosChallenge);
          }
          res.status(503);
          next(new Error('Sorry, we are temporarily not available! Please try again later.'));
        } else {
          res.status(410); 
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + err.message + ' (' + file.originalname + ')'));
        }
      }
    } else {
      res.status(410);
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'));
    }
  } else {
    res.status(204).end();
  }

}



module.exports = {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload
}
