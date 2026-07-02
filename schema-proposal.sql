-- EXCITE plus Vital DB research platform schema proposal
-- 핵심 변경: 도메인별 table은 선택적 template이며, 연구별 custom data schema를 허용한다.

CREATE TABLE research_project (
  research_project_id TEXT PRIMARY KEY,
  research_project_name TEXT NOT NULL,
  research_topic TEXT,
  description TEXT,
  irb_number TEXT,
  status TEXT,
  created_by TEXT,
  created_at TIMESTAMP,
  updated_at TIMESTAMP
);

CREATE TABLE research_tag (
  tag_id TEXT PRIMARY KEY,
  tag_name TEXT NOT NULL UNIQUE,
  tag_description TEXT,
  color TEXT,
  created_by TEXT,
  created_at TIMESTAMP,
  updated_at TIMESTAMP
);

CREATE TABLE research_custom_table_definition (
  table_def_id TEXT PRIMARY KEY,
  research_project_id TEXT REFERENCES research_project(research_project_id),
  table_name TEXT NOT NULL,
  target_level TEXT, -- patient, episode, vital_file, dataset, timepoint, sample, custom
  description TEXT,
  created_by TEXT,
  created_at TIMESTAMP
);

CREATE TABLE research_custom_column_definition (
  column_def_id TEXT PRIMARY KEY,
  table_def_id TEXT REFERENCES research_custom_table_definition(table_def_id),
  column_name TEXT NOT NULL,
  data_type TEXT NOT NULL, -- text, numeric, datetime, category, boolean
  unit TEXT,
  is_required BOOLEAN DEFAULT FALSE,
  description TEXT
);

CREATE TABLE vital_file_metadata (
  vital_file_id TEXT PRIMARY KEY,
  case_id TEXT,
  file_name TEXT NOT NULL,
  file_type TEXT,
  file_size BIGINT,
  uploaded_by TEXT,
  uploaded_at TIMESTAMP,
  subject_id TEXT,
  event_or_episode_id TEXT,
  matched_to_event BOOLEAN,
  match_method TEXT,
  recording_start_datetime TIMESTAMP,
  recording_end_datetime TIMESTAMP,
  duration_min NUMERIC,
  processed_status TEXT,
  processing_version TEXT,
  note TEXT
);

CREATE TABLE data_tag_mapping (
  mapping_id TEXT PRIMARY KEY,
  tag_id TEXT REFERENCES research_tag(tag_id),
  research_project_id TEXT REFERENCES research_project(research_project_id),
  target_type TEXT NOT NULL, -- patient, episode, vital_file, dataset, lab, outcome, custom_table_row
  target_id TEXT NOT NULL,
  assigned_by TEXT,
  assigned_at TIMESTAMP,
  note TEXT
);
