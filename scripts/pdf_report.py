"""Build a paginated contribution report from documented design and actual evidence."""
import json
import re
from html import escape
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, PageBreak, Image, LongTable, Preformatted
from reportlab.platypus.tableofcontents import TableOfContents

STYLES=getSampleStyleSheet()
STYLES.add(ParagraphStyle(name='SmallText',parent=STYLES['BodyText'],fontSize=8,leading=11))
STYLES.add(ParagraphStyle(name='CodeBlock',fontName='Courier',fontSize=7,leading=9,spaceAfter=9))
STYLES['BodyText'].leading=14
STYLES['BodyText'].spaceAfter=8
WIDTH=A4[0]-96

class Report(BaseDocTemplate):
    def __init__(self, filename):
        super().__init__(filename,pagesize=A4,leftMargin=48,rightMargin=48,topMargin=54,bottomMargin=48,title='Joseph Awaida — Sprint I Services 7–9',author='Joseph Awaida')
        frame=Frame(48,48,WIDTH,A4[1]-102,id='content')
        self.addPageTemplates(PageTemplate(id='report',frames=[frame],onPage=self.footer))
    def footer(self,canvas,doc):
        canvas.saveState()
        canvas.setFont('Helvetica',8)
        canvas.setFillColor(colors.HexColor('#526879'))
        canvas.drawString(48,28,'Joseph Awaida | Services 7, 8, 9 | Sprint I')
        canvas.drawRightString(A4[0]-48,28,str(doc.page))
        canvas.restoreState()
    def afterFlowable(self,flowable):
        if isinstance(flowable,Paragraph) and flowable.style.name=='Heading1':
            self.notify('TOCEntry',(0,flowable.getPlainText(),self.page))

def paragraph(text,style='BodyText'):
    return Paragraph(escape(text),STYLES[style])

def table(rows,widths=None):
    converted=[[paragraph(str(value),'SmallText') for value in row] for row in rows]
    result=LongTable(converted,colWidths=widths,repeatRows=1,hAlign='LEFT')
    result.setStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#deebf4')),('GRID',(0,0),(-1,-1),.3,colors.HexColor('#a5b8c8')),('VALIGN',(0,0),(-1,-1),'TOP'),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f5f8fb')]),('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5)])
    return result

def build():
    story=[Spacer(1,inch),paragraph('Security Incident Detection and Response Management System','Title'),Spacer(1,24),paragraph('Sprint I — Services 7, 8, 9','Heading1'),paragraph('Joseph Awaida'),paragraph('18 October 2026'),paragraph('Contribution report: merge into the common team report before submission.'),paragraph('Repository: https://github.com/j123awaida/435L'),PageBreak(),paragraph('Table of contents','Heading1')]
    toc=TableOfContents()
    toc.levelStyles=[ParagraphStyle(name='TOC',fontName='Helvetica',fontSize=10,leading=16,leftIndent=0)]
    story += [toc,PageBreak()]
    for line in Path('docs/REPORT.md').read_text().splitlines():
        if not line.strip() or line.startswith('# ') or line.startswith('!['):
            continue
        if line.startswith('## '):
            story += [paragraph(line[3:],'Heading1')]
        elif line.startswith('### '):
            story += [paragraph(line[4:],'Heading2')]
        else:
            story += [paragraph(line)]
    story += [PageBreak(),paragraph('Design diagrams (Joseph Awaida)','Heading1')]
    for name in ('architecture','schema'):
        path=Path('docs')/(name+'.png')
        if path.exists():
            image=Image(str(path)); ratio=min(WIDTH/image.imageWidth,610/image.imageHeight)
            image.drawWidth=image.imageWidth*ratio; image.drawHeight=image.imageHeight*ratio
            story += [paragraph(name.capitalize(),'Heading2'),image,Spacer(1,14)]
    evidence=Path('evidence/http-execution.json')
    if evidence.exists():
        records=json.loads(evidence.read_text())
        story += [PageBreak(),paragraph('Actual execution evidence (Joseph Awaida)','Heading1'),paragraph('Captured from the local running APIs at '+records['captured_at']+'. This appendix contains execution records, not Postman desktop screenshots.')]
        summary=Path('evidence/validation-summary.json')
        if summary.exists():
            values=json.loads(summary.read_text()); p=values['pytest']; n=values['newman']
            story += [paragraph(f'Pytest: {p["tests"]} tests, {p["failures"]} failures, {p["errors"]} errors. Postman Newman: {n["requests"]["total"]} requests and {n["assertions"]["total"]} assertions; {n["assertions"]["failed"]} failed assertions.')]
        story += [table([['Operation','Expected HTTP','Actual HTTP']]+[[r['name'],r['expected_status'],r['actual_status']] for r in records['results']],[WIDTH-140,70,70])]
        for name in ('Create critical vulnerability','Advance vulnerability to Resolved','Create employee alert','Mark own notification read','Retrieve completed workflow','Reject another user notification'):
            r=next(x for x in records['results'] if x['name']==name)
            story += [paragraph('Joseph Awaida — '+name,'Heading2'),paragraph(r['method']+' '+r['url'],'SmallText'),paragraph('Actual request (credentials omitted):','SmallText'),Preformatted(json.dumps(r['request_body'],indent=2),STYLES['CodeBlock'],maxLineLength=92),paragraph('Actual response: HTTP '+str(r['actual_status']),'SmallText'),Preformatted(json.dumps(r['response'],indent=2),STYLES['CodeBlock'],maxLineLength=92)]
    schema=Path('evidence/database-schema.json')
    if schema.exists():
        story += [PageBreak(),paragraph('Database structure observed locally (Joseph Awaida)','Heading1')]
        for record in json.loads(schema.read_text()):
            if record['table'] in ('sessions','notification_receipts'):
                continue
            story += [paragraph(record['table'],'Heading2'),table([['Field','Type','Primary key','Required']]+[[c['name'],c['type'],bool(c['pk']),bool(c['notnull'])] for c in record['columns']],[WIDTH*.45,WIDTH*.2,WIDTH*.175,WIDTH*.175])]
    transitions=Path('evidence/database-transitions.json')
    if transitions.exists():
        story += [PageBreak(),paragraph('Before/after database records (Joseph Awaida)','Heading1'),paragraph('These records were queried from the actual SQLite database immediately before and after each operation. Concurrent alert delivery may add other notifications. They supplement the required database screenshots.')]
        wanted=('Advance vulnerability to Resolved','Mark own notification read','Step 1 Completed')
        for name in wanted:
            record=next(r for r in json.loads(transitions.read_text()) if r['operation']==name)
            story += [paragraph(name,'Heading2')]
            for phase in ('before','after'):
                rows=record[phase]
                columns=['id','status']+(['read_date'] if record['table']=='notifications' else ['completion_date'] if record['table']=='actions' else ['resolution_date'])
                story += [paragraph(phase.capitalize()+' — '+record['table'],'SmallText'),table([columns]+[[r.get(c) for c in columns] for r in rows],[45,105,WIDTH-150])]
    story += [PageBreak(),paragraph('API reference (Joseph Awaida)','Heading1')]
    for line in Path('docs/API.md').read_text().splitlines():
        if line.startswith('### '):
            story.append(paragraph(line[4:],'Heading3'))
        elif line.startswith('## '):
            story.append(paragraph(line[3:],'Heading2'))
        elif line and not line.startswith('# '):
            story.append(paragraph(line,'SmallText'))
    story += [PageBreak(),paragraph('Submission status and remaining evidence (Joseph Awaida)','Heading1')]
    for line in Path('docs/SUBMISSION-CHECKLIST.md').read_text().splitlines():
        if line and not line.startswith('#'):
            story.append(paragraph(line))
    Report('docs/Joseph-Awaida-Sprint-I-Report.pdf').multiBuild(story)
    print('Created paginated PDF with table of contents, diagrams, and actual execution/database records.')

if __name__=='__main__':
    build()
