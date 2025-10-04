"""
Funções utilitárias para notebooks (carregamento, checks, agregações).
Importe com: from pandas.utils_pandas import <func>
"""

import pandas as pd

def quick_nulls(df: pd.DataFrame) -> pd.Series:
    """Retorna contagem de nulos por coluna."""
    return df.isna().sum().sort_values(ascending=False)

def ensure_datetime(df: pd.DataFrame, col: str) -> pd.DataFrame:
    """Converte coluna para datetime no lugar (inplace) e retorna df."""
    df[col] = pd.to_datetime(df[col], errors="coerce", utc=False)
    return df
