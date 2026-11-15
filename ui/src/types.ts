export interface Page<T> { items: T[]; next_cursor: string | null }
export interface Range { minimum: number | null; maximum: number | null }
export interface CompanyProfile {
  name: string; aliases: string[]; domains: string[]; industry: string | null;
  countries: string[]; employees: Range | null;
  revenue: (Range & { currency: string | null; period: string | null }) | null;
  technologies: string[];
}
export interface Company extends CompanyProfile {
  id: string; profile_version: number; created_at: string; updated_at: string;
}
export type AlertStatus = 'open' | 'resolved' | 'dismissed_not_targeted'
export interface Evidence { post_version_id: string; quote: string }
export interface Alert {
  matched_target_ids?: string[];
  id: string; company_id: string; title: string; category: string;
  severity: 'low' | 'medium' | 'high' | 'critical'; status: AlertStatus;
  confidence: number; explanation: string; matching_attributes: string[];
  conflicting_attributes: string[]; missing_information: string[];
  suggested_actions: string[]; evidence: Evidence[]; created_at: string; updated_at: string;
}
export interface AlertEvent {
  id: string; previous_status: AlertStatus; status: AlertStatus; actor: 'user' | 'model';
  reason: string; note: string; created_at: string; evidence: Evidence[];
}
export interface AlertDetail { alert: Alert; events: AlertEvent[] }
export interface TargetFacts {
  company_names: string[]; domains: string[]; industry: string | null; countries: string[];
  employees: Range | null; revenue: (Range & { currency: string | null; period: string | null }) | null;
  technologies: string[]; evidence: { field: string; quote: string }[];
}
export interface PostTarget { id: string; label: string; facts: TargetFacts }
export interface PostVersion {
  id: string;
  targets?: PostTarget[];
  classification: { category: string; reason: string; target_extraction_status?: 'complete' | 'review_required' };
  post: { title: string; text: string; url: string; author: string | null;
    published_at: string | null; fetched_at: string };
}
export interface PostListItem {
  version_id: string; post_id: string; source_name: string; title: string; excerpt: string;
  category: string; published_at: string | null; fetched_at: string; embedding_ready?: boolean;
}
export interface PostListPage extends Page<PostListItem> { total_count: number }
export interface Job {
  analysis_scope?: 'full_corpus' | 'daily_candidates';
  coverage?: {
    selected?: number; deferred?: number; excluded?: number; pending_embeddings?: number;
    superseded?: number; superseded_assignments?: number; candidate_limit_reached?: boolean;
  };
  id: string; state: 'queued' | 'running' | 'succeeded' | 'failed' | 'incomplete';
  processed_count: number; total_count: number | null; error: string | null; created_at: string; finished_at?: string | null;
}
