# ml/

`nuclei_model.pkl` - the saved capstone severity model: TF-IDF (1-2 grams,
min_df=2, sublinear tf, 60k features) + LinearSVC (C=0.5, class_weight
balanced), fitted on 13,718 deduplicated Nuclei templates. Labels:
info/low/medium/high/critical.

Load with scikit-learn 1.7.2 / numpy 2.2.6 (see requirements.txt).
`backend/services/severity_model.py` replicates the exact training-time
cleaning; the pickle does not embed it.

Scope: trained to predict Nuclei template authors' severity ratings. On
this scanner's LLM-written findings it is an unvalidated second opinion,
shown in the UI as "ML" - it never replaces the analysis severity.
