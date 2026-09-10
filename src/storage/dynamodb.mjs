import crypto from "node:crypto";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
  BatchWriteCommand,
  UpdateCommand
} from "@aws-sdk/lib-dynamodb";

const PK_APP = "APP";
const SK_POLICY = "POLICY";
const PK_EVENT = "EVENT";

function getTableName() {
  const name = process.env.DYNAMODB_TABLE_NAME || "";
  if (!name) {
    throw new Error("DYNAMODB_TABLE_NAME is required for Lambda deployments.");
  }
  return name;
}

function parseCsv(value) {
  if (!value) return [];
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function docClient() {
  const client = new DynamoDBClient({});
  return DynamoDBDocumentClient.from(client, {
    marshallOptions: { removeUndefinedValues: true }
  });
}

function envSeedPolicy() {
  return {
    blockedTerms: parseCsv(process.env.BLOCKED_TERMS),
    blockedToolNames: parseCsv(process.env.BLOCKED_TOOL_NAMES),
    updatedAt: new Date().toISOString()
  };
}

export async function getPolicyConfig() {
  const ddb = docClient();
  const table = getTableName();
  const out = await ddb.send(
    new GetCommand({
      TableName: table,
      Key: { pk: PK_APP, sk: SK_POLICY }
    })
  );

  if (out.Item) {
    return {
      blockedTerms: out.Item.blockedTerms || [],
      blockedToolNames: out.Item.blockedToolNames || [],
      updatedAt: out.Item.updatedAt || new Date().toISOString()
    };
  }

  const seed = envSeedPolicy();
  await ddb.send(
    new PutCommand({
      TableName: table,
      Item: {
        pk: PK_APP,
        sk: SK_POLICY,
        blockedTerms: seed.blockedTerms,
        blockedToolNames: seed.blockedToolNames,
        updatedAt: seed.updatedAt
      }
    })
  );
  return seed;
}

export async function putPolicyConfig(next) {
  const ddb = docClient();
  const table = getTableName();
  const updatedAt = new Date().toISOString();
  await ddb.send(
    new PutCommand({
      TableName: table,
      Item: {
        pk: PK_APP,
        sk: SK_POLICY,
        blockedTerms: next.blockedTerms,
        blockedToolNames: next.blockedToolNames,
        updatedAt
      }
    })
  );
  return { ...next, updatedAt };
}

function sortKeyForEvent() {
  const inv = String(1e15 - Date.now()).padStart(15, "0");
  return `${inv}#${crypto.randomUUID()}`;
}

export async function appendObservabilityEvent(event) {
  const ddb = docClient();
  const table = getTableName();
  const out = await ddb.send(
    new UpdateCommand({
      TableName: table,
      Key: { pk: PK_APP, sk: "_META" },
      UpdateExpression: "SET eventSeq = if_not_exists(eventSeq, :z) + :one",
      ExpressionAttributeValues: { ":z": 0, ":one": 1 },
      ReturnValues: "UPDATED_NEW"
    })
  );

  const id = Number(out.Attributes?.eventSeq ?? 0);
  const sk = sortKeyForEvent();
  const timestamp = new Date().toISOString();

  await ddb.send(
    new PutCommand({
      TableName: table,
      Item: {
        pk: PK_EVENT,
        sk,
        id,
        timestamp,
        ...event
      }
    })
  );
}

export async function listObservabilityEvents(limit) {
  const ddb = docClient();
  const table = getTableName();
  const out = await ddb.send(
    new QueryCommand({
      TableName: table,
      KeyConditionExpression: "pk = :p",
      ExpressionAttributeValues: { ":p": PK_EVENT },
      Limit: limit,
      ScanIndexForward: true
    })
  );

  return (out.Items || []).map((row) => {
    const { pk, sk, ...rest } = row;
    return rest;
  });
}

export async function clearObservabilityEvents() {
  const ddb = docClient();
  const table = getTableName();
  let lastKey;
  do {
    const out = await ddb.send(
      new QueryCommand({
        TableName: table,
        KeyConditionExpression: "pk = :p",
        ExpressionAttributeValues: { ":p": PK_EVENT },
        ExclusiveStartKey: lastKey,
        ProjectionExpression: "pk, sk"
      })
    );

    const keys = (out.Items || []).map((i) => ({ pk: i.pk, sk: i.sk }));
    for (let i = 0; i < keys.length; i += 25) {
      const batch = keys.slice(i, i + 25);
      await ddb.send(
        new BatchWriteCommand({
          RequestItems: {
            [table]: batch.map((k) => ({ DeleteRequest: { Key: k } }))
          }
        })
      );
    }
    lastKey = out.LastEvaluatedKey;
  } while (lastKey);
}

export function sanitizePolicyConfig(config) {
  return {
    blockedTerms: Array.isArray(config.blockedTerms) ? config.blockedTerms : [],
    blockedToolNames: Array.isArray(config.blockedToolNames) ? config.blockedToolNames : []
  };
}

export function normalizeStringList(value, fieldName) {
  if (!Array.isArray(value)) {
    throw new Error(`"${fieldName}" must be an array of strings.`);
  }

  const normalized = value
    .map((entry) => {
      if (typeof entry !== "string") {
        throw new Error(`"${fieldName}" must contain only strings.`);
      }
      return entry.trim();
    })
    .filter(Boolean);

  return Array.from(new Set(normalized));
}

export function getObsMaxEvents() {
  return Math.max(10, Number(process.env.OBS_MAX_EVENTS || 200));
}
