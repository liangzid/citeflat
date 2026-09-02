# CAITLYN Paper

USENIX-formatted paper describing CAITLYN (Continuous Agents for Injection
Threats via Lifelong Yielding Nexus) defense middleware for LLM agents.
The submission targets the 36th USENIX Security Symposium (USENIX Security
'27), August 11--13, 2027, Denver, CO.

## Structure

- `main.tex` — main paper source (anonymized submission draft); includes the
  per-section files below
- `sections/` — per-section sources: Introduction, Background and Threat Model,
  System Design, Initial Library, Evolution Tree Structure, Evaluation,
  Discussion, Related Work, Conclusion, and the Ethics / Open Science
  appendices
- `main.bib` — bibliography
- `usenix.sty` — official USENIX Security '27 style file
- `usenixsecurity2027.tex` — official USENIX Security '27 LaTeX template
- `template.tex` — older USENIX template (historical reference)

## USENIX Security '27 CFP Compliance

Key requirements from the official call for papers:

- Anonymous double-blind submission: no author names or affiliations on the
  title page, and no identity-revealing text. This draft uses an
  `Anonymous Author(s)` block and omits acknowledgments.
- Body text limited to 13 pages, excluding references and appendices.
  Initial submissions may have unlimited appendices and references; final
  camera-ready papers are limited to 20 total pages.
- Mandatory Open Science appendix describing artifacts and anonymous access.
- Ethics appendix recommended (no longer mandatory).
- Formatting: U.S. letter, two-column, 10-point Times Roman, 12-point leading,
  in a 7" x 9" text block.

Important Cycle 1 deadlines (AoE): mandatory registration August 18, 2026;
paper submissions August 25, 2026; artifacts August 28, 2026; notifications
December 3, 2026.

## Required LaTeX Packages

Beyond a standard texlive installation:

- `algorithm`, `algpseudocode` — algorithm pseudocode
- `listings` — code listings
- `cleveref` — smart cross-references
- `booktabs` — professional tables
- `tikz` — architecture diagram

On Ubuntu/Debian:
```
sudo apt install texlive-latex-extra texlive-science texlive-pictures
```

## Compilation

```
pdflatex main
bibtex main
pdflatex main
pdflatex main
```

Or with latexmk:
```
latexmk -pdf main
```

## Anonymization Notes

Before submission, replace the `Anonymous Author(s)` block only after
acceptance, restore acknowledgments for the camera-ready version, and fill in
the anonymous artifact URL in the Open Science appendix. Do not link to the
public GitHub repository in the submission.

## Paper Contents

- **Figure 1**: System architecture diagram (TikZ)
- **Algorithm 1**: Two-Tier Scanning Pipeline (pseudocode)
- **Algorithm 2**: Evolution Loop (pseudocode)
- **Table 1**: Evolution Loop Tool Set
- **Table 2**: Initial Antigen Library
- **Figure 2**: Antibody Forest Structure (TikZ)

8 sections: Introduction → Background → System Design → Initial Library → Forest Structure → Discussion → Related Work → Conclusion
