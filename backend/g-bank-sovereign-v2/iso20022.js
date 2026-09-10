'use strict';

const { sha256 } = require('../g-bank-live-v1/canonical');
const { isValidIban, normalizeIban } = require('./accounts');

function xml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function assertId(name, value) {
  const v = String(value || '');
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,34}$/.test(v)) throw new Error(`${name}_invalid`);
  return v;
}

function assertBic(value) {
  const bic = String(value || '').toUpperCase();
  if (!/^[A-Z0-9]{8}([A-Z0-9]{3})?$/.test(bic)) throw new Error('bic_invalid');
  return bic;
}

function assertName(name, value) {
  const v = String(value || '').trim();
  if (!v || v.length > 140) throw new Error(`${name}_invalid`);
  return v;
}

function amountValue(amountMinor) {
  const n = Number(amountMinor);
  if (!Number.isSafeInteger(n) || n <= 0) throw new Error('amount_minor_invalid');
  return (n / 100).toFixed(2);
}

function assertEuro(currency) {
  if (String(currency || '').toUpperCase() !== 'EUR') throw new Error('sepa_currency_must_be_eur');
  return 'EUR';
}

function iban(value, field) {
  const v = normalizeIban(value);
  if (!isValidIban(v)) throw new Error(`${field}_iban_invalid`);
  return v;
}

function addressXml(address) {
  if (!address) return '';
  const country = String(address.country || '').toUpperCase();
  const town = String(address.town || '').trim();
  if (!/^[A-Z]{2}$/.test(country) || !town) throw new Error('structured_address_required');
  const lines = [
    address.street ? `<StrtNm>${xml(address.street)}</StrtNm>` : '',
    address.building_number ? `<BldgNb>${xml(address.building_number)}</BldgNb>` : '',
    address.post_code ? `<PstCd>${xml(address.post_code)}</PstCd>` : '',
    `<TwnNm>${xml(town)}</TwnNm>`,
    `<Ctry>${xml(country)}</Ctry>`,
  ].join('');
  return `<PstlAdr>${lines}</PstlAdr>`;
}

function partyXml(tag, party) {
  return `<${tag}><Nm>${xml(assertName(`${tag}_name`, party?.name))}</Nm>${addressXml(party?.address)}</${tag}>`;
}

function transferFields(input) {
  const currency = assertEuro(input.currency);
  return {
    amount: amountValue(input.amount_minor),
    currency,
    debtor_iban: iban(input.debtor_iban, 'debtor'),
    creditor_iban: iban(input.creditor_iban, 'creditor'),
    debtor_name: assertName('debtor_name', input.debtor?.name),
    creditor_name: assertName('creditor_name', input.creditor?.name),
    end_to_end_id: assertId('end_to_end_id', input.end_to_end_id),
    instruction_id: assertId('instruction_id', input.instruction_id),
    message_id: assertId('message_id', input.message_id),
    remittance: String(input.remittance || '').slice(0, 140),
  };
}

function wrapResult(messageType, document, scheme) {
  return Object.freeze({
    schema: 'g-bank-iso20022-message/v2',
    scheme,
    message_type: messageType,
    iso20022_version: '2019',
    document,
    document_sha256: sha256(document),
  });
}

function buildPain001(input, { instant = false, now = new Date() } = {}) {
  const f = transferFields(input);
  const debtor = { ...input.debtor, name: f.debtor_name };
  const creditor = { ...input.creditor, name: f.creditor_name };
  const creation = now.toISOString();
  const executionDate = creation.slice(0, 10);
  const localInstrument = instant ? '<LclInstrm><Prtry>INST</Prtry></LclInstrm>' : '';
  const doc = `<?xml version="1.0" encoding="UTF-8"?>` +
    `<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pain.001.001.09">` +
    `<CstmrCdtTrfInitn>` +
    `<GrpHdr><MsgId>${xml(f.message_id)}</MsgId><CreDtTm>${xml(creation)}</CreDtTm><NbOfTxs>1</NbOfTxs><CtrlSum>${f.amount}</CtrlSum><InitgPty><Nm>${xml(f.debtor_name)}</Nm></InitgPty></GrpHdr>` +
    `<PmtInf><PmtInfId>${xml(f.instruction_id)}</PmtInfId><PmtMtd>TRF</PmtMtd><BtchBookg>false</BtchBookg><NbOfTxs>1</NbOfTxs><CtrlSum>${f.amount}</CtrlSum>` +
    `<PmtTpInf><SvcLvl><Cd>SEPA</Cd></SvcLvl>${localInstrument}</PmtTpInf>` +
    `<ReqdExctnDt><Dt>${executionDate}</Dt></ReqdExctnDt>` +
    `${partyXml('Dbtr', debtor)}<DbtrAcct><Id><IBAN>${f.debtor_iban}</IBAN></Id></DbtrAcct>` +
    `<CdtTrfTxInf><PmtId><InstrId>${xml(f.instruction_id)}</InstrId><EndToEndId>${xml(f.end_to_end_id)}</EndToEndId></PmtId>` +
    `<Amt><InstdAmt Ccy="EUR">${f.amount}</InstdAmt></Amt>` +
    `${partyXml('Cdtr', creditor)}<CdtrAcct><Id><IBAN>${f.creditor_iban}</IBAN></Id></CdtrAcct>` +
    (f.remittance ? `<RmtInf><Ustrd>${xml(f.remittance)}</Ustrd></RmtInf>` : '') +
    `</CdtTrfTxInf></PmtInf></CstmrCdtTrfInitn></Document>`;
  return wrapResult('pain.001.001.09', doc, instant ? 'SCT_INST' : 'SCT');
}

function buildPacs008(input, { instant = false, now = new Date() } = {}) {
  const f = transferFields(input);
  const debtorBic = assertBic(input.debtor_agent_bic);
  const creditorBic = assertBic(input.creditor_agent_bic);
  const debtor = { ...input.debtor, name: f.debtor_name };
  const creditor = { ...input.creditor, name: f.creditor_name };
  const creation = now.toISOString();
  const txId = assertId('transaction_id', input.transaction_id || f.instruction_id);
  const localInstrument = instant ? '<LclInstrm><Prtry>INST</Prtry></LclInstrm>' : '';
  const doc = `<?xml version="1.0" encoding="UTF-8"?>` +
    `<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08">` +
    `<FIToFICstmrCdtTrf>` +
    `<GrpHdr><MsgId>${xml(f.message_id)}</MsgId><CreDtTm>${xml(creation)}</CreDtTm><NbOfTxs>1</NbOfTxs><SttlmInf><SttlmMtd>CLRG</SttlmMtd></SttlmInf></GrpHdr>` +
    `<CdtTrfTxInf><PmtId><InstrId>${xml(f.instruction_id)}</InstrId><EndToEndId>${xml(f.end_to_end_id)}</EndToEndId><TxId>${xml(txId)}</TxId></PmtId>` +
    `<PmtTpInf><SvcLvl><Cd>SEPA</Cd></SvcLvl>${localInstrument}</PmtTpInf>` +
    `<IntrBkSttlmAmt Ccy="EUR">${f.amount}</IntrBkSttlmAmt><ChrgBr>SLEV</ChrgBr>` +
    `<DbtrAgt><FinInstnId><BICFI>${xml(debtorBic)}</BICFI></FinInstnId></DbtrAgt>${partyXml('Dbtr', debtor)}<DbtrAcct><Id><IBAN>${f.debtor_iban}</IBAN></Id></DbtrAcct>` +
    `<CdtrAgt><FinInstnId><BICFI>${xml(creditorBic)}</BICFI></FinInstnId></CdtrAgt>${partyXml('Cdtr', creditor)}<CdtrAcct><Id><IBAN>${f.creditor_iban}</IBAN></Id></CdtrAcct>` +
    (f.remittance ? `<RmtInf><Ustrd>${xml(f.remittance)}</Ustrd></RmtInf>` : '') +
    `</CdtTrfTxInf></FIToFICstmrCdtTrf></Document>`;
  return wrapResult('pacs.008.001.08', doc, instant ? 'SCT_INST' : 'SCT');
}

function buildPacs008SctInst(input, options = {}) {
  return buildPacs008(input, { ...options, instant: true });
}

module.exports = { buildPain001, buildPacs008, buildPacs008SctInst, xml, assertBic };
