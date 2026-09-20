#!/usr/bin/env python3
"""Assemble the complete research and smaller journal-upload archives."""
from pathlib import Path
import hashlib,json,zipfile,shutil,re
import fitz
R=Path(__file__).resolve().parents[1]
D=R.parent
# Update document checks from the final compiled versions.
quality={}
for n in ['manuscript','supplement']:
    p=R/'paper'/f'{n}.pdf';doc=fitz.open(p);tex=(R/'paper'/f'{n}.tex').read_text();log=(R/'paper'/f'{n}.log').read_text();text='\n'.join(page.get_text()for page in doc)
    quality[n]={'pages':len(doc),'references':(R/'paper'/f'{n}.bbl').read_text().count('\\bibitem'),'undefined_references_or_citations':('undefined' in log),'overfull_boxes':log.count('Overfull'),'em_dashes':text.count('—'),'replacement_glyphs':text.count('\ufffd'),'author_boxes_or_status_labels':any(x in tex for x in ['tcolorbox','Evidence status','Evidence required','Research manuscript working draft','\\todo{','\\status{'])}
    if n=='manuscript':quality[n]['abstract_words']=len(tex.split('\\begin{abstract}')[1].split('\\keywords')[0].split())
    assert not any(quality[n][k]for k in ['undefined_references_or_citations','overfull_boxes','em_dashes','replacement_glyphs','author_boxes_or_status_labels'])
(R/'analysis/document_quality.json').write_text(json.dumps(quality,indent=2))
# Scientific archive excludes development probes/pilots, obsolete build logs and QA sheets.
raw_roots={'measurements','security_controls','transparency','simulations'}
allowed_logs={'analysis.txt','measurements.txt','measurements_extended.txt','measurements_stage2.txt','security_controls.txt','final_tests.txt','final_models.txt','final_pdf_build.txt','transparency.txt'}
allow_paper_ext={'.tex','.bib','.bbl','.cls','.clo','.pdf','.eps','.png','.json'}
paths=[]
for p in sorted(R.rglob('*')):
    if not p.is_file():continue
    rel=p.relative_to(R);parts=rel.parts
    if '__pycache__'in parts or p.suffix in {'.pyc','.pid'}:continue
    if parts[0]in {'qa'}:continue
    if parts[0]=='raw'and(len(parts)<2 or parts[1]not in raw_roots):continue
    if parts[0]=='logs'and p.name not in allowed_logs:continue
    if parts[0]=='paper'and p.suffix not in allow_paper_ext:continue
    if parts[0]=='analysis'and p.suffix in {'.jpg','.png'}:continue
    if p.name=='SHA256SUMS.txt':continue
    paths.append(p)
manifest=''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.relative_to(R).as_posix()+'\n'for p in paths)
(R/'SHA256SUMS.txt').write_text(manifest);paths.append(R/'SHA256SUMS.txt')
full=D/'QUIC_Complete_Research_Package.zip'
with zipfile.ZipFile(full,'w',zipfile.ZIP_DEFLATED,compresslevel=6)as z:
    for p in paths:z.write(p,'QUIC_Research/'+p.relative_to(R).as_posix())
small=D/'QUIC_Journal_LaTeX_and_PDF.zip'
with zipfile.ZipFile(small,'w',zipfile.ZIP_DEFLATED,compresslevel=6)as z:
    for p in paths:
        rel=p.relative_to(R)
        if rel.parts[0]=='paper' and p.suffix in {'.tex','.bib','.bbl','.cls','.clo','.pdf','.eps','.json'}:
            z.write(p,'QUIC_Journal/'+rel.relative_to('paper').as_posix())
    z.write(R/'SUBMISSION_NOTES.txt','QUIC_Journal/SUBMISSION_NOTES.txt')
    z.write(R/'THIRD_PARTY_NOTICES.txt','QUIC_Journal/THIRD_PARTY_NOTICES.txt')
    z.write(R/'scripts/build_pdfs.sh','QUIC_Journal/build_pdfs.sh')
shutil.copy2(R/'paper/manuscript.pdf',D/'QUIC_Revised_Manuscript.pdf')
shutil.copy2(R/'paper/supplement.pdf',D/'QUIC_Supplementary_Information.pdf')
with zipfile.ZipFile(full)as z:
    bad=z.testzip();assert bad is None,bad
with zipfile.ZipFile(small)as z:
    bad=z.testzip();assert bad is None,bad
print(json.dumps({'documents':quality,'research_files':len(paths),'research_zip_bytes':full.stat().st_size,'journal_zip_bytes':small.stat().st_size,'zip_crc_checks':'passed'},indent=2))
