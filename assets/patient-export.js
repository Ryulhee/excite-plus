/* EXCITE plus patient / ECMO Excel export
   Browser-only prototype exporter. Uses the locally vendored JSZip library to
   generate a standards-compliant .xlsx workbook without sending data outside
   the browser. */
(function (root) {
  'use strict';

  const STORE_KEY = 'excite_plus_vitaldb_state_v2';
  const EXCEL_MIME = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

  function text(value) {
    return value === null || value === undefined ? '' : String(value);
  }

  function xmlEscape(value) {
    return text(value)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&apos;');
  }

  function readState() {
    try {
      const parsed = JSON.parse(root.localStorage?.getItem(STORE_KEY) || '{}');
      return Object.assign({
        patients: [], ecmoEpisodes: [], vitalFiles: [], assignments: [],
        monitorAssignments: [], labRecords: [], microbiologyRecords: []
      }, parsed || {});
    } catch (error) {
      console.warn('Excel export state read failed', error);
      return { patients: [], ecmoEpisodes: [], vitalFiles: [], assignments: [], monitorAssignments: [], labRecords: [], microbiologyRecords: [] };
    }
  }

  function safeDateValue(value) {
    if (!value) return Number.POSITIVE_INFINITY;
    const time = new Date(value).getTime();
    return Number.isFinite(time) ? time : Number.POSITIVE_INFINITY;
  }

  function koCompare(a, b) {
    return text(a).localeCompare(text(b), 'ko-KR', { numeric: true, sensitivity: 'base' });
  }

  function registrationCompare(a, b) {
    const left = text(a).replace(/\D/g, '');
    const right = text(b).replace(/\D/g, '');
    if (left.length !== right.length) return left.length - right.length;
    return left.localeCompare(right, 'en', { numeric: true });
  }

  function episodeStart(episode) {
    return episode?.events?.ecmoStartTime || episode?.ecmoStartTime || episode?.startTime || '';
  }

  function episodeFinish(episode) {
    return episode?.events?.ecmoFinishTime || episode?.ecmoFinishTime || episode?.finishTime || '';
  }

  function episodeLabel(episode) {
    if (!episode) return '';
    return episode.label || `${episode.sequence || 1}차 ECMO`;
  }

  function episodesForPatient(state, patientId) {
    return (state.ecmoEpisodes || [])
      .filter(episode => episode.patientId === patientId)
      .slice()
      .sort((a, b) => {
        const startDiff = safeDateValue(episodeStart(a)) - safeDateValue(episodeStart(b));
        if (Number.isFinite(startDiff) && startDiff !== 0) return startDiff;
        return Number(a.sequence || 0) - Number(b.sequence || 0) || koCompare(a.createdAt, b.createdAt);
      });
  }

  function filesForPatient(state, patientId) {
    return (state.vitalFiles || [])
      .filter(file => file.patientId === patientId)
      .slice()
      .sort((a, b) => Number(a.linkedOrder || 999999) - Number(b.linkedOrder || 999999)
        || safeDateValue(a.matchedTime || a.recordingStart) - safeDateValue(b.matchedTime || b.recordingStart)
        || koCompare(a.name, b.name));
  }

  function patientName(patient) {
    return patient?.initials || patient?.patientInitials || '';
  }


  function patientTags(state, patientId) {
    return (state.assignments || [])
      .filter(item => item.targetId === patientId && (!item.targetType || item.targetType === 'patient'))
      .map(item => Array.isArray(item.path) && item.path.length ? item.path.join(' → ') : item.tagName)
      .filter(Boolean)
      .filter((value, index, array) => array.indexOf(value) === index);
  }

  function monitorLabel(state, file) {
    const assignment = (state.monitorAssignments || []).find(item => item.id === file.monitorAssignmentId);
    const source = assignment || file || {};
    const key = source.monitorKey || [source.room, source.monitorNumber].filter(Boolean).join(' ');
    return text(key || file.assignedMonitor || file.monitor || '').trim();
  }

  function outcomeLabel(episode) {
    if (!episode) return '';
    if (episode.dischargeAlive === 'dead' || episode.events?.deathDate) return '사망';
    if (episode.dischargeAlive === 'alive') return '생존퇴원';
    if (episode.dischargeAlive === 'unknown') return '미상';
    return '';
  }

  function patientEarliestEcmo(state, patient) {
    const values = episodesForPatient(state, patient.id).map(episode => safeDateValue(episodeStart(episode)));
    return values.length ? Math.min(...values) : Number.POSITIVE_INFINITY;
  }

  function orderedPatients(state, sortMode, patientIds) {
    let patients = (state.patients || []).slice();
    if (patientIds instanceof Set) patients = patients.filter(patient => patientIds.has(patient.id));
    const fallback = (a, b) => registrationCompare(a.registrationNo, b.registrationNo) || koCompare(patientName(a), patientName(b));
    if (sortMode === 'name') {
      patients.sort((a, b) => koCompare(patientName(a), patientName(b)) || fallback(a, b));
    } else if (sortMode === 'ecmo-time') {
      patients.sort((a, b) => patientEarliestEcmo(state, a) - patientEarliestEcmo(state, b) || fallback(a, b));
    } else {
      patients.sort((a, b) => fallback(a, b));
    }
    return patients;
  }

  function annualIndexMap(patients) {
    return new Map(patients.map((patient, index) => [patient.id, index + 1]));
  }

  function patientRows(state, patients) {
    const rows = [];
    patients.forEach((patient, patientIndex) => {
      const episodes = episodesForPatient(state, patient.id);
      const patientFiles = filesForPatient(state, patient.id);
      const csvNames = patientFiles.map(file => file.name || file.caseId).filter(Boolean);
      const monitors = patientFiles.map(file => monitorLabel(state, file)).filter(Boolean)
        .filter((value, index, array) => array.indexOf(value) === index);
      const tags = patientTags(state, patient.id);
      const effectiveEpisodes = episodes.length ? episodes : [null];
      effectiveEpisodes.forEach((episode, episodeIndex) => {
        rows.push({
          'Annual No': episodeIndex === 0 ? patientIndex + 1 : '',
          'Patient Initials': patientName(patient),
          '등록번호': text(patient.registrationNo),
          'ECMO Start Time': episodeStart(episode),
          'ECMO Finish Time': episodeFinish(episode),
          'Intubation Start Time': episode?.events?.intubationStartTime || '',
          'Admission Date': patient.admissionDate || patient.addmissionDate || '',
          'Gender': patient.sex || patient.gender || '',
          'Birth date': patient.birthDate || '',
          'Height': patient.heightCm ?? patient.height ?? '',
          'Weight': patient.weightKg ?? patient.weight ?? '',
          'ECMO Episode': episodeLabel(episode),
          'Uploaded CSV Count': patientFiles.length,
          'CSV Names': csvNames.join('\n'),
          'Assigned Monitors': monitors.join('\n'),
          'Research Tags': tags.join('\n'),
          'Outcome': outcomeLabel(episode)
        });
      });
    });
    return rows;
  }

  function csvRows(state, patients) {
    const annual = annualIndexMap(patients);
    const rows = [];
    patients.forEach(patient => {
      const episodes = new Map(episodesForPatient(state, patient.id).map(episode => [episode.id, episode]));
      filesForPatient(state, patient.id).forEach((file, index) => {
        rows.push({
          'Annual No': annual.get(patient.id),
          'Patient Initials': patientName(patient),
          '등록번호': text(patient.registrationNo),
          'ECMO Episode': file.episodeId ? episodeLabel(episodes.get(file.episodeId)) : '환자에만 연결',
          'CSV Order': Number(file.linkedOrder || index + 1),
          'CSV Name': file.name || '',
          'Case ID': file.caseId || '',
          'Assigned Monitor': monitorLabel(state, file),
          'Recording Start': file.recordingStart || '',
          'Matched Time': file.matchedTime || '',
          'Timepoint Label': file.timepointLabel || '',
          'Uploaded At': file.uploadedAt || '',
          'Match Status': file.matchStatus || file.autoMatchStatus || '',
          'File Size': file.size || file.bytes || ''
        });
      });
    });
    return rows;
  }

  function preEcmoRows(state, patients) {
    const annual = annualIndexMap(patients);
    const rows = [];
    patients.forEach(patient => {
      episodesForPatient(state, patient.id).forEach(episode => {
        const pre = episode.measurements?.preEcmo || {};
        const vital = pre.vitalVentFlow || {};
        const abga = pre.abga || {};
        const labs = pre.labs || {};
        rows.push({
          'Annual No': annual.get(patient.id), 'Patient Initials': patientName(patient), '등록번호': text(patient.registrationNo), 'ECMO Episode': episodeLabel(episode), 'ECMO Start Time': episodeStart(episode),
          'Pre-ECMO Check Time': pre.checkDateTime || '',
          'Vent': vital.Vent ?? '', 'Mode': vital.Mode ?? '', 'FiO2': vital.FiO2 ?? '', 'RR': vital.RR ?? '', 'PEEP': vital.PEEP ?? '',
          'Flow rate': vital['Flow rate'] ?? '', 'O2': vital.O2 ?? '', 'O2 Unit': vital['O2 Unit'] ?? '',
          'SBP': vital.SBP ?? '', 'DBP': vital.DBP ?? '', 'Mean BP': vital['Mean BP'] ?? '', 'PR': vital.PR ?? '',
          'pH': abga.pH ?? '', 'PCO2': abga.PCO2 ?? '', 'PO2': abga.PO2 ?? '', 'HCO3': abga.HCO3 ?? '', 'SaO2': abga.SaO2 ?? '', 'Lactate': abga.Lactate ?? '',
          'Creatinine': labs.Creatinine ?? '', 'Hgb': labs.Hgb ?? '', 'Plt': labs.Plt ?? '', 'INR': labs.INR ?? '', 'APTT': labs.APTT ?? labs.APPT ?? '',
          'AST': labs.AST ?? '', 'ALT': labs.ALT ?? '', 'Bilirubin': labs.Bilirubin ?? '', 'Albumin': labs.Albumin ?? '', 'CRP': labs.CRP ?? '',
          'ESR': labs.ESR ?? '', 'proBNP': labs.proBNP ?? '', 'Myoglobin': labs.Myoglobin ?? '', 'CK-MB': labs['CK-MB'] ?? '',
          'Troponin I': labs['Troponin I'] ?? '', 'Troponin T': labs['Troponin T'] ?? ''
        });
      });
    });
    return rows;
  }

  function preExtendedRows(state, patients) {
    const annual = annualIndexMap(patients);
    const rows = [];
    patients.forEach(patient => episodesForPatient(state, patient.id).forEach(episode => {
      const tests = episode.measurements?.preEcmo?.extendedTests || [];
      tests.forEach(test => rows.push({
        'Annual No': annual.get(patient.id), 'Patient Initials': patientName(patient), '등록번호': text(patient.registrationNo),
        'ECMO Episode': episodeLabel(episode), 'ECMO Start Time': episodeStart(episode),
        'Test': test.test || '', 'Value': test.value ?? '', 'Unit': test.unit || '', 'Test Time': test.dateTime || '',
        'Reference': test.reference || '', 'Source Linked': test.sourceLinked || '', 'Note': test.note || ''
      }));
    }));
    return rows;
  }


  function postEcmoRows(state, patients) {
    const annual = annualIndexMap(patients);
    const rows = [];
    patients.forEach(patient => episodesForPatient(state, patient.id).forEach(episode => {
      const post = episode.measurements?.postEcmo || {};
      const vital = post.vital || {};
      const abga = post.abga || {};
      const labs = post.labs || {};
      const vent = episode.measurements?.ventEnd || {};
      rows.push({
        'Annual No': annual.get(patient.id), 'Patient Initials': patientName(patient), '등록번호': text(patient.registrationNo),
        'ECMO Episode': episodeLabel(episode), 'Post-ECMO Check Time': post.checkDateTime || '',
        'ECMO Finish Time': episodeFinish(episode), 'Extubation Time': episode.events?.extubationDateTime || '',
        'Vent': vent.Vent ?? '', 'Mode': vent.Mode ?? '', 'FiO2': vent.FiO2 ?? '', 'RR': vent.RR ?? '', 'PEEP': vent.PEEP ?? '', 'PIP': vent.PIP ?? '',
        'SBP': vital.SBP ?? '', 'DBP': vital.DBP ?? '', 'Mean BP': vital['Mean BP'] ?? '', 'PR': vital.PR ?? '',
        'pH': abga.pH ?? '', 'PCO2': abga.PCO2 ?? '', 'PO2': abga.PO2 ?? '', 'HCO3': abga.HCO3 ?? '', 'SaO2': abga.SaO2 ?? '', 'Lactate': abga.Lactate ?? '',
        'Creatinine': labs.Creatinine ?? '', 'Hgb': labs.Hgb ?? '', 'Plt': labs.Plt ?? '', 'CRP': labs.CRP ?? '', 'Post-ECMO Note': post.note || ''
      });
    }));
    return rows;
  }

  function intraEcmoRows(state, patients) {
    const annual = annualIndexMap(patients);
    const rows = [];
    const points = [
      ['beforeGcs', 'GCS 전'], ['fourHour', '4시간 경과'], ['twentyFourHour', '24시간 경과']
    ];
    patients.forEach(patient => episodesForPatient(state, patient.id).forEach(episode => {
      const during = episode.measurements?.duringEcmo || {};
      points.forEach(([key, fallbackLabel]) => {
        const section = during[key] || {};
        const pump = section.pump || {};
        const abga = section.abga || {};
        const vent = section.vent || {};
        const hemo = section.hemodynamics || {};
        rows.push({
          'Annual No': annual.get(patient.id), 'Patient Initials': patientName(patient), '등록번호': text(patient.registrationNo), 'ECMO Episode': episodeLabel(episode), 'ECMO Start Time': episodeStart(episode),
          'Timepoint': section.label || fallbackLabel, 'Check Time': section.checkDateTime || '',
          'Pump Flow': pump.Flow ?? section.pumpFlow ?? '', 'RPM': pump.RPM ?? '', 'ECMO FiO2': pump.FiO2 ?? '', 'Sweep gas': pump['Sweep gas'] ?? '',
          'pH': abga.pH ?? '', 'PCO2': abga.PCO2 ?? '', 'PO2': abga.PO2 ?? '', 'HCO3': abga.HCO3 ?? '', 'SaO2': abga.SaO2 ?? '', 'Lactate': abga.Lactate ?? '',
          'Vent Mode': vent.Mode ?? '', 'Vent FiO2': vent.FiO2 ?? '', 'RR': vent.RR ?? '', 'PEEP': vent.PEEP ?? '',
          'SBP': hemo.SBP ?? '', 'DBP': hemo.DBP ?? ''
        });
      });
    }));
    return rows;
  }

  function durationHours(start, finish) {
    const a = safeDateValue(start);
    const b = safeDateValue(finish);
    if (!Number.isFinite(a) || !Number.isFinite(b) || a === Number.POSITIVE_INFINITY || b === Number.POSITIVE_INFINITY || b < a) return '';
    return Math.round((b - a) / 360000) / 10;
  }

  function outcomeRows(state, patients) {
    const annual = annualIndexMap(patients);
    const rows = [];
    patients.forEach(patient => episodesForPatient(state, patient.id).forEach(episode => {
      const events = episode.events || {};
      const details = episode.details || {};
      rows.push({
        'Annual No': annual.get(patient.id), 'Patient Initials': patientName(patient), '등록번호': text(patient.registrationNo),
        'ECMO Episode': episodeLabel(episode), 'ECMO Type': details.ecmoType || '', 'ECMO Mode': details.ecmoMode || '', 'Location': details.location || '',
        'ECMO Start Time': episodeStart(episode), 'ECMO Finish Time': episodeFinish(episode), 'ECMO Duration (hours)': durationHours(episodeStart(episode), episodeFinish(episode)),
        'Intubation Start Time': events.intubationStartTime || '', 'Extubation Time': events.extubationDateTime || '',
        'ICU Discharge Time': events.icuDischargeDateTime || '', 'Admission Date': patient.admissionDate || patient.addmissionDate || '',
        'Discharge Date': events.dischargeDate || '', 'Death Date': events.deathDate || '', 'Discharge Alive': episode.dischargeAlive || '',
        'Outcome': outcomeLabel(episode), 'CRRT': details.crrtFlag || '', 'CRRT Start': details.crrtStart || '', 'CRRT End': details.crrtEnd || '',
        'CRRT Mode': details.crrtMode || '', 'Complications': details.complications || '', 'Last Follow-up Date': details.lastFollowupDate || '',
        'Creatinine 28d': details.creatinine28d || '', 'Creatinine 28d Unit': details.creatinine28dUnit || '', 'Episode Note': episode.note || ''
      });
    }));
    return rows;
  }

  const BASELINE_CONDITIONS = [
    ['hypertension', 'Hypertension'], ['diabetes', 'Diabetes'], ['pulmonaryTb', 'Pulmonary TB'], ['hepatitis', 'Hepatitis'],
    ['cancer', 'Cancer'], ['operationHistory', 'Operation History'], ['stroke', 'Stroke'], ['hyperlipidemia', 'Hyperlipidemia'],
    ['padCarotid', 'PAD / Carotid Disease'], ['allergy', 'Allergy'], ['medication', 'Medication']
  ];

  function baselineRows(state, patients) {
    const annual = annualIndexMap(patients);
    return patients.map(patient => {
      const row = {
        'Annual No': annual.get(patient.id), 'Patient Initials': patientName(patient), '등록번호': text(patient.registrationNo),
        'Admission Date': patient.admissionDate || patient.addmissionDate || '', 'Gender': patient.sex || '', 'Birth date': patient.birthDate || '',
        'Height': patient.heightCm ?? '', 'Weight': patient.weightKg ?? '', 'Baseline Date': patient.baselineDate || ''
      };
      BASELINE_CONDITIONS.forEach(([key, label]) => {
        row[label] = patient.baselineConditions?.[key]?.status || '';
        row[`${label} Note`] = patient.baselineConditions?.[key]?.note || '';
      });
      return row;
    });
  }

  function labRows(state, patients) {
    const annual = annualIndexMap(patients);
    const patientMap = new Map(patients.map(patient => [patient.id, patient]));
    const episodeMap = new Map((state.ecmoEpisodes || []).map(episode => [episode.id, episode]));
    return (state.labRecords || []).filter(record => patientMap.has(record.patientId)).map(record => {
      const patient = patientMap.get(record.patientId);
      return {
        'Annual No': annual.get(patient.id), 'Patient Initials': patientName(patient), '등록번호': text(patient.registrationNo),
        'ECMO Episode': episodeLabel(episodeMap.get(record.episodeId)), 'Test Date': record.date || '', 'WBC': record.wbc ?? '', 'CRP': record.crp ?? '',
        'Procalcitonin': record.pct ?? record.procalcitonin ?? '', 'Created At': record.createdAt || ''
      };
    });
  }

  function microbiologyRows(state, patients) {
    const annual = annualIndexMap(patients);
    const patientMap = new Map(patients.map(patient => [patient.id, patient]));
    const episodeMap = new Map((state.ecmoEpisodes || []).map(episode => [episode.id, episode]));
    return (state.microbiologyRecords || []).filter(record => patientMap.has(record.patientId)).map(record => {
      const patient = patientMap.get(record.patientId);
      return {
        'Annual No': annual.get(patient.id), 'Patient Initials': patientName(patient), '등록번호': text(patient.registrationNo),
        'ECMO Episode': episodeLabel(episodeMap.get(record.episodeId)), 'Test Date': record.date || '', 'Collection Time': record.collectionTime || '',
        'Specimen Site': record.specimenSite || '', 'Organism': record.organismName || '', 'Result': record.result || '', 'Culture Set': record.cultureSet || '',
        'Susceptibility': record.susceptibility || '', 'Lab Institute': record.labInstitute || '', 'Created At': record.createdAt || ''
      };
    });
  }

  function rowsToMatrix(rows, preferredHeaders) {
    const headers = preferredHeaders && preferredHeaders.length
      ? preferredHeaders
      : rows.reduce((all, row) => {
        Object.keys(row || {}).forEach(key => { if (!all.includes(key)) all.push(key); });
        return all;
      }, []);
    return [headers, ...rows.map(row => headers.map(header => row?.[header] ?? ''))];
  }

  function buildSheets(state, patients, sortMode, includeMain = true) {
    const suffix = sortMode === 'name' ? '이니셜' : sortMode === 'ecmo-time' ? 'ECMO시간' : '등록번호';
    const sheets = [];
    if (includeMain) sheets.push({ name: `Patient_ECMO_${suffix}`, rows: patientRows(state, patients) });
    sheets.push(
      { name: 'CSV_Mapping', rows: csvRows(state, patients) },
      { name: 'Pre_ECMO', rows: preEcmoRows(state, patients) },
      { name: 'Pre_Extended', rows: preExtendedRows(state, patients) },
      { name: 'Post_ECMO', rows: postEcmoRows(state, patients) },
      { name: 'Intra_ECMO', rows: intraEcmoRows(state, patients) },
      { name: 'Outcome', rows: outcomeRows(state, patients) },
      { name: 'Baseline', rows: baselineRows(state, patients) },
      { name: 'Lab_Records', rows: labRows(state, patients) },
      { name: 'Microbiology', rows: microbiologyRows(state, patients) }
    );
    return sheets;
  }

  function columnName(index) {
    let result = '';
    let value = index;
    while (value > 0) {
      value -= 1;
      result = String.fromCharCode(65 + (value % 26)) + result;
      value = Math.floor(value / 26);
    }
    return result;
  }

  function cellXml(value, ref, styleIndex) {
    const style = styleIndex ? ` s="${styleIndex}"` : '';
    if (typeof value === 'number' && Number.isFinite(value)) return `<c r="${ref}"${style} t="n"><v>${value}</v></c>`;
    if (typeof value === 'boolean') return `<c r="${ref}"${style} t="b"><v>${value ? 1 : 0}</v></c>`;
    const clean = text(value).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '');
    return `<c r="${ref}"${style} t="inlineStr"><is><t xml:space="preserve">${xmlEscape(clean)}</t></is></c>`;
  }

  function sheetXml(matrix) {
    const data = matrix.length ? matrix : [['No data']];
    const maxCols = Math.max(1, ...data.map(row => row.length));
    const lastRef = `${columnName(maxCols)}${data.length}`;
    const widths = Array.from({ length: maxCols }, (_, colIndex) => {
      const maxLength = Math.max(...data.slice(0, 2000).map(row => text(row[colIndex]).split('\n').reduce((m, part) => Math.max(m, part.length), 0)), 8);
      const header = text(data[0]?.[colIndex]);
      const longColumn = /CSV Names|Research Tags|Assigned Monitors|Note|Complication|Susceptibility|Medication|History/i.test(header);
      return Math.min(longColumn ? 48 : 28, Math.max(10, maxLength + 2));
    });
    const cols = widths.map((width, index) => `<col min="${index + 1}" max="${index + 1}" width="${width}" customWidth="1"/>`).join('');
    const rows = data.map((row, rowIndex) => {
      const rowNumber = rowIndex + 1;
      const cells = Array.from({ length: maxCols }, (_, colIndex) => cellXml(row[colIndex] ?? '', `${columnName(colIndex + 1)}${rowNumber}`, rowIndex === 0 ? 1 : 2)).join('');
      return `<row r="${rowNumber}" ht="${rowIndex === 0 ? 26 : 20}" customHeight="1">${cells}</row>`;
    }).join('');
    return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<dimension ref="A1:${lastRef}"/><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>
<sheetFormatPr defaultRowHeight="20"/><cols>${cols}</cols><sheetData>${rows}</sheetData><autoFilter ref="A1:${lastRef}"/><pageMargins left="0.25" right="0.25" top="0.5" bottom="0.5" header="0.2" footer="0.2"/></worksheet>`;
  }

  function stylesXml() {
    return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="2"><font><sz val="10"/><name val="Aptos"/><family val="2"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="10"/><name val="Aptos"/><family val="2"/></font></fonts>
<fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF0B1F3A"/><bgColor indexed="64"/></patternFill></fill></fills>
<borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border><border><left style="thin"><color rgb="FFE4E9E6"/></left><right style="thin"><color rgb="FFE4E9E6"/></right><top style="thin"><color rgb="FFE4E9E6"/></top><bottom style="thin"><color rgb="FFE4E9E6"/></bottom><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf></cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles><dxfs count="0"/><tableStyles count="0" defaultTableStyle="TableStyleMedium2" defaultPivotStyle="PivotStyleLight16"/></styleSheet>`;
  }

  function sanitizeSheetName(name, used) {
    let clean = text(name).replace(/[\\/*?:\[\]]/g, '_').slice(0, 31) || 'Sheet';
    const original = clean;
    let index = 2;
    while (used.has(clean)) {
      const suffix = `_${index++}`;
      clean = `${original.slice(0, 31 - suffix.length)}${suffix}`;
    }
    used.add(clean);
    return clean;
  }

  async function createWorkbookArchive(sheetModels, outputType) {
    const JSZipRef = root.JSZip || (typeof require === 'function' ? require('jszip') : null);
    if (!JSZipRef) throw new Error('JSZip library is not available.');
    const zip = new JSZipRef();
    const usedNames = new Set();
    const sheets = sheetModels.map(model => ({
      name: sanitizeSheetName(model.name, usedNames),
      matrix: rowsToMatrix(model.rows || [], model.headers)
    }));
    const workbookSheets = sheets.map((sheet, index) => `<sheet name="${xmlEscape(sheet.name)}" sheetId="${index + 1}" r:id="rId${index + 1}"/>`).join('');
    const workbookRels = sheets.map((sheet, index) => `<Relationship Id="rId${index + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${index + 1}.xml"/>`).join('');
    const styleRelId = sheets.length + 1;
    const contentOverrides = sheets.map((sheet, index) => `<Override PartName="/xl/worksheets/sheet${index + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`).join('');
    const now = new Date().toISOString();

    zip.file('[Content_Types].xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>${contentOverrides}<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>`);
    zip.folder('_rels').file('.rels', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>`);
    zip.folder('docProps').file('core.xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>EXCITE Patient ECMO Export</dc:title><dc:creator>EXCITE plus</dc:creator><cp:lastModifiedBy>EXCITE plus</cp:lastModifiedBy><dcterms:created xsi:type="dcterms:W3CDTF">${now}</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">${now}</dcterms:modified></cp:coreProperties>`);
    zip.folder('docProps').file('app.xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><Application>EXCITE plus</Application><DocSecurity>0</DocSecurity><ScaleCrop>false</ScaleCrop><HeadingPairs><vt:vector size="2" baseType="variant"><vt:variant><vt:lpstr>Worksheets</vt:lpstr></vt:variant><vt:variant><vt:i4>${sheets.length}</vt:i4></vt:variant></vt:vector></HeadingPairs><TitlesOfParts><vt:vector size="${sheets.length}" baseType="lpstr">${sheets.map(sheet => `<vt:lpstr>${xmlEscape(sheet.name)}</vt:lpstr>`).join('')}</vt:vector></TitlesOfParts><Company>EXCITE Team</Company><LinksUpToDate>false</LinksUpToDate><SharedDoc>false</SharedDoc><HyperlinksChanged>false</HyperlinksChanged><AppVersion>1.0</AppVersion></Properties>`);
    zip.folder('xl').file('workbook.xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><bookViews><workbookView xWindow="0" yWindow="0" windowWidth="24000" windowHeight="12000"/></bookViews><sheets>${workbookSheets}</sheets><calcPr calcId="191029"/></workbook>`);
    zip.folder('xl').folder('_rels').file('workbook.xml.rels', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${workbookRels}<Relationship Id="rId${styleRelId}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`);
    zip.folder('xl').file('styles.xml', stylesXml());
    sheets.forEach((sheet, index) => zip.folder('xl').folder('worksheets').file(`sheet${index + 1}.xml`, sheetXml(sheet.matrix)));
    return zip.generateAsync({ type: outputType || 'blob', compression: 'DEFLATE', compressionOptions: { level: 6 }, mimeType: EXCEL_MIME });
  }

  function exportFileName(sortMode, allVersions) {
    const date = new Date();
    const ymd = `${date.getFullYear()}${String(date.getMonth() + 1).padStart(2, '0')}${String(date.getDate()).padStart(2, '0')}`;
    const label = allVersions ? 'all-sort-versions' : sortMode === 'name' ? 'initials-order' : sortMode === 'ecmo-time' ? 'ecmo-time-order' : 'registration-order';
    return `EXCITE_patient_ECMO_${label}_${ymd}.xlsx`;
  }

  function visiblePatientIds() {
    if (!root.document) return null;
    const ids = Array.from(root.document.querySelectorAll('[data-integrated-patient]')).map(element => element.dataset.integratedPatient).filter(Boolean);
    return new Set(ids);
  }

  function showStatus(message, tone) {
    const status = root.document?.getElementById('patientExcelExportStatus');
    if (!status) return;
    status.textContent = message;
    status.className = `excel-export-status ${tone || ''}`.trim();
  }

  async function runBrowserExport() {
    const sortSelect = root.document.getElementById('patientExcelSortMode');
    const scopeSelect = root.document.getElementById('patientExcelScope');
    const button = root.document.getElementById('patientExcelDownloadBtn');
    const sortMode = sortSelect?.value || 'name';
    const allVersions = sortMode === 'all';
    const state = readState();
    const filterIds = scopeSelect?.value === 'filtered' ? visiblePatientIds() : null;
    if (!(state.patients || []).length) {
      showStatus('내보낼 환자가 없습니다.', 'warning');
      return;
    }
    button.disabled = true;
    showStatus('엑셀 파일을 만드는 중입니다…', 'working');
    try {
      let sheets = [];
      if (allVersions) {
        const namePatients = orderedPatients(state, 'name', filterIds);
        if (!namePatients.length) { showStatus('현재 필터 조건에 해당하는 환자가 없습니다.', 'warning'); return; }
        const regPatients = orderedPatients(state, 'registration', filterIds);
        const timePatients = orderedPatients(state, 'ecmo-time', filterIds);
        sheets = [
          { name: 'Patient_ECMO_이니셜', rows: patientRows(state, namePatients) },
          { name: 'Patient_ECMO_등록번호', rows: patientRows(state, regPatients) },
          { name: 'Patient_ECMO_ECMO시간', rows: patientRows(state, timePatients) },
          ...buildSheets(state, namePatients, 'name', false)
        ];
      } else {
        const patients = orderedPatients(state, sortMode, filterIds);
        if (!patients.length) { showStatus('현재 필터 조건에 해당하는 환자가 없습니다.', 'warning'); return; }
        sheets = buildSheets(state, patients, sortMode, true);
      }
      const blob = await createWorkbookArchive(sheets, 'blob');
      const url = URL.createObjectURL(blob);
      const anchor = root.document.createElement('a');
      anchor.href = url;
      anchor.download = exportFileName(sortMode, allVersions);
      root.document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      showStatus(`완료: ${allVersions ? '정렬 3종' : '선택한 정렬'}과 임상 시트를 저장했습니다.`, 'success');
    } catch (error) {
      console.error(error);
      showStatus(`엑셀 생성 실패: ${error.message || error}`, 'error');
    } finally {
      button.disabled = false;
    }
  }

  function initUi() {
    const toggle = root.document?.getElementById('patientExcelExportToggle');
    const menu = root.document?.getElementById('patientExcelExportMenu');
    const button = root.document?.getElementById('patientExcelDownloadBtn');
    if (!toggle || !menu || !button) return;
    toggle.addEventListener('click', event => {
      event.stopPropagation();
      menu.classList.toggle('open');
      toggle.setAttribute('aria-expanded', String(menu.classList.contains('open')));
    });
    menu.addEventListener('click', event => event.stopPropagation());
    root.document.addEventListener('click', () => {
      menu.classList.remove('open');
      toggle.setAttribute('aria-expanded', 'false');
    });
    button.addEventListener('click', runBrowserExport);
  }

  const api = {
    readState, orderedPatients, patientRows, csvRows, preEcmoRows, intraEcmoRows,
    outcomeRows, baselineRows, buildSheets, rowsToMatrix, createWorkbookArchive
  };
  root.EXCITEPatientExport = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root.document) root.document.addEventListener('DOMContentLoaded', initUi);
})(typeof window !== 'undefined' ? window : globalThis);
