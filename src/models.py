"""Shared model-evaluation helpers (metrics + plots). Accuracy is reported but never used alone."""
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score, precision_recall_curve,
                             precision_score, recall_score, roc_auc_score, roc_curve)

from utils import save_fig


def binary_metrics(y_true, score, y_pred, name):
    """Security-oriented binary metrics. `score` = higher means more likely attack."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "model": name,
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall_attack": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "roc_auc": roc_auc_score(y_true, score),
        "pr_auc": average_precision_score(y_true, score),
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        "accuracy": (tp + tn) / len(y_true),
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }


def plot_confusion(y_true, y_pred, labels, title, name, normalize=None):
    cm = confusion_matrix(y_true, y_pred, labels=labels, normalize=normalize)
    fig, ax = plt.subplots(figsize=(max(4.5, len(labels) * 0.9), max(3.8, len(labels) * 0.75)))
    sns.heatmap(cm, annot=True, fmt=".2f" if normalize else ",d", cmap="Blues",
                xticklabels=labels, yticklabels=labels, ax=ax, cbar=False)
    ax.set_xlabel("predicted")
    ax.set_ylabel("actual")
    ax.set_title(title)
    save_fig(fig, name)
    return cm


def plot_curves(y_true, scores: dict, title, name):
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
    for label, s in scores.items():
        fpr, tpr, _ = roc_curve(y_true, s)
        p, r, _ = precision_recall_curve(y_true, s)
        axes[0].plot(fpr, tpr, label=f"{label} (AUC {roc_auc_score(y_true, s):.3f})")
        axes[1].plot(r, p, label=f"{label} (AP {average_precision_score(y_true, s):.3f})")
    axes[0].plot([0, 1], [0, 1], "k--", lw=0.8)
    axes[0].set(xlabel="false positive rate", ylabel="true positive rate (recall)", title=f"ROC - {title}")
    axes[1].axhline(np.mean(y_true), color="k", ls="--", lw=0.8, label="baseline (prevalence)")
    axes[1].set(xlabel="recall", ylabel="precision", title=f"Precision-Recall - {title}")
    for ax in axes:
        ax.legend(fontsize=8, loc="lower right" if ax is axes[0] else "lower left")
    save_fig(fig, name)


def metrics_table(rows):
    df = pd.DataFrame(rows)
    num = df.select_dtypes(include="number").columns.difference(["tp", "fp", "tn", "fn"])
    df[num] = df[num].round(4)
    return df
