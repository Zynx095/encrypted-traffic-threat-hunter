"""
Phase 6 Step 8: Experimental Dataset Constructor
"""
import pandas as pd
import numpy as np
import hashlib
import time
from typing import Dict, List, Tuple
from sklearn.model_selection import GroupShuffleSplit

class ExperimentConstructor:
    def __init__(self, model_safe_df: pd.DataFrame, provenance_df: pd.DataFrame, random_state: int = 42):
        self.ms_df = model_safe_df.copy()
        self.prov_df = provenance_df.copy()
        self.random_state = random_state

        # Merge source_file into ms_df temporarily for grouping logic
        self.full_df = self.ms_df.merge(self.prov_df[['model_safe_index', 'source_file', 'dataset_id']], on='model_safe_index')

        self.flat_feature_cols = [c for c in self.ms_df.columns if not c.startswith("sequence_") and c not in ["model_safe_index", "label"]]
        self.tls_structural_cols = [c for c in ["tls_version", "clienthello_present", "serverhello_present", "sni_present", "alpn_value"] if c in self.ms_df.columns]
        self.flow_stat_cols = [c for c in self.flat_feature_cols if c not in self.tls_structural_cols and c not in ["ja3_string", "ja3_hash", "ja3s_string", "ja3s_hash", "ja4"]]

        # Hash the feature vector to create a behavioral group ID
        def hash_row(row):
            # Sort keys to ensure deterministic string
            row_dict = {k: v for k, v in row.items() if pd.notnull(v)}
            row_str = str(sorted(row_dict.items()))
            return hashlib.sha256(row_str.encode()).hexdigest()

        self.full_df['behavioral_hash'] = self.full_df[self.flat_feature_cols].apply(hash_row, axis=1)

    def analyze_duplicates(self) -> Dict:
        """Analyzes duplicate behavioral geometries across datasets and labels."""
        dupe_mask = self.full_df.duplicated(subset=['behavioral_hash'], keep=False)
        dupe_df = self.full_df[dupe_mask]

        cross_pcap_groups = 0
        cross_label_groups = 0

        if not dupe_df.empty:
            grouped = dupe_df.groupby('behavioral_hash')
            for _, group in grouped:
                if group['source_file'].nunique() > 1:
                    cross_pcap_groups += 1
                if group['label'].nunique() > 1:
                    cross_label_groups += 1

        return {
            "exact_duplicate_count": len(dupe_df),
            "duplicate_groups": self.full_df['behavioral_hash'].nunique() - (len(self.full_df) - len(dupe_df)), # total unique hashes minus singletons
            "cross_pcap_duplicate_groups": cross_pcap_groups,
            "cross_label_duplicate_groups": cross_label_groups
        }

    def _split_data(self, df: pd.DataFrame, group_col: str = 'behavioral_hash') -> Tuple[pd.DataFrame, pd.DataFrame]:
        # If dataset is too small to group by source_file safely without dropping a class,
        # behavioral_hash guarantees exact duplicates stay together without decimating classes.

        # Determine grouping strategy:
        # If we group by source_file, we only have 8 groups. GroupShuffleSplit might fail to represent both classes in test.
        # Let's use behavioral_hash to strictly keep duplicates together.

        gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=self.random_state)

        # It's possible for GSS to fail if there's only 1 group.
        if df[group_col].nunique() <= 1:
            return df.copy(), pd.DataFrame(columns=df.columns)

        train_idx, test_idx = next(gss.split(df, groups=df[group_col]))

        return df.iloc[train_idx].copy(), df.iloc[test_idx].copy()

    def generate_experiment_A(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Flow only. No fingerprints."""
        cols = ['model_safe_index', 'label'] + self.flow_stat_cols + self.tls_structural_cols
        # Include sequences for Phase 7
        seq_cols = [c for c in self.ms_df.columns if c.startswith("sequence_")]
        cols += seq_cols

        df = self.full_df[cols + ['behavioral_hash']].copy()

        train_df, test_df = self._split_data(df)
        return train_df.drop(columns=['behavioral_hash']), test_df.drop(columns=['behavioral_hash'])

    def generate_experiment_B(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """JA3 only."""
        cols = ['model_safe_index', 'label', 'ja3_hash', 'behavioral_hash']
        df = self.full_df[cols].copy()
        df = df[df['ja3_hash'].notnull()]

        train_df, test_df = self._split_data(df)
        return train_df.drop(columns=['behavioral_hash']), test_df.drop(columns=['behavioral_hash'])

    def generate_experiment_C(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """JA4 only."""
        cols = ['model_safe_index', 'label', 'ja4', 'behavioral_hash']
        df = self.full_df[cols].copy()
        df = df[df['ja4'].notnull()]

        train_df, test_df = self._split_data(df)
        return train_df.drop(columns=['behavioral_hash']), test_df.drop(columns=['behavioral_hash'])

    def generate_experiment_D(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """JA3 + Flow."""
        cols = ['model_safe_index', 'label', 'ja3_hash'] + self.flow_stat_cols + self.tls_structural_cols
        seq_cols = [c for c in self.ms_df.columns if c.startswith("sequence_")]
        cols += seq_cols

        df = self.full_df[cols + ['behavioral_hash']].copy()
        df = df[df['ja3_hash'].notnull()]

        train_df, test_df = self._split_data(df)
        return train_df.drop(columns=['behavioral_hash']), test_df.drop(columns=['behavioral_hash'])

    def generate_experiment_E(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """JA4 + Flow."""
        cols = ['model_safe_index', 'label', 'ja4'] + self.flow_stat_cols + self.tls_structural_cols
        seq_cols = [c for c in self.ms_df.columns if c.startswith("sequence_")]
        cols += seq_cols

        df = self.full_df[cols + ['behavioral_hash']].copy()
        df = df[df['ja4'].notnull()]

        train_df, test_df = self._split_data(df)
        return train_df.drop(columns=['behavioral_hash']), test_df.drop(columns=['behavioral_hash'])
