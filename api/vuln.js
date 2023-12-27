'use strict';
 
const uuid = require('uuid');
const AWS = require('aws-sdk'); 
 
AWS.config.setPromisesDependency(require('bluebird'));
 
const dynamoDb = new AWS.DynamoDB.DocumentClient();
 
module.exports.submit = (event, context, callback) => {
  const requestBody = JSON.parse(event.body);
  const projId = requestBody.projId;
  const projVerId = requestBody.projVerId;
  const compId = requestBody.compId;
  const comply = requestBody.comply;
 
  if (typeof projId !== 'number' || typeof projVerId !== 'number' || typeof compId !== 'number' ||  typeof comply !== 'boolean') {
    console.error('Validation Failed');
    callback(new Error('Couldn\'t submit vuln because of validation errors.'));
    return;
  }
 
  submitVuln(vulnInfo(projId, projVerId, compId, comply))
    .then(res => {
      callback(null, {
        statusCode: 200,
        body: JSON.stringify({
          message: `Sucessfully submitted vuln with ID ${res.id}`,
        })
      });
    })
    .catch(err => {
      console.log(err);
      callback(null, {
        statusCode: 500,
        body: JSON.stringify({
          message: `Unable to submit vuln for project ID  ${projId}`
        })
      })
    });
};
 
	
module.exports.list = (event, context, callback) => {
  var params = {
      TableName: process.env.VULN_TABLE,
      ProjectionExpression: "id, projID, projVerID, compID, comply"
  };

  console.log("Scanning Vuln table.");
  const onScan = (err, data) => {
      if (err) {
          console.log('Scan failed to load data. Error JSON:', JSON.stringify(err, null, 2));
          callback(err);
      } else {
          console.log("Scan succeeded.");
          return callback(null, {
              statusCode: 200,
              body: JSON.stringify({
                  vuln: data.Items
              })
          });
      }

  };

  dynamoDb.scan(params, onScan);

};
 
const submitVuln = vuln => {
  console.log('Submitting vuln');
  const vulnInfo = {
    TableName: process.env.VULN_TABLE,
    Item: vuln,
  };
  return dynamoDb.put(vulnInfo).promise()
    .then(res => vuln);
};
 
const vulnInfo = (projId, projVerId, compId, comply) => {
  const timestamp = new Date().getTime();
  return {
    id: uuid.v1(),
    projId: projId,
    projVerId: projVerId,
    compId: compId,
    comply: comply,
    submittedAt: timestamp,
    updatedAt: timestamp,
  };
};