// make_reference.js — génère reference.docx pour pandoc
// marges 2.5 cm, Times New Roman 12pt, numérotation pied de page, styles h1-h4

const {
  Document, Packer, Paragraph, TextRun,
  Header, Footer, PageNumber,
  AlignmentType, HeadingLevel, LevelFormat,
  BorderStyle, WidthType
} = require('docx');
const fs = require('fs');

// 1 cm = 567 DXA (1 inch = 1440 DXA, 1 inch = 2.54 cm)
const CM = 567;

const doc = new Document({
  styles: {
    default: {
      document: {
        run: { font: 'Times New Roman', size: 24 }  // 12pt
      }
    },
    paragraphStyles: [
      {
        id: 'Normal',
        name: 'Normal',
        run: { font: 'Times New Roman', size: 24 },
        paragraph: {
          spacing: { after: 120, line: 276, lineRule: 'auto' },
          alignment: AlignmentType.JUSTIFIED
        }
      },
      {
        id: 'Heading1',
        name: 'Heading 1',
        basedOn: 'Normal',
        next: 'Normal',
        quickFormat: true,
        run: { font: 'Arial', size: 32, bold: true, color: '1F3864' },
        paragraph: {
          spacing: { before: 360, after: 180 },
          outlineLevel: 0,
          alignment: AlignmentType.LEFT
        }
      },
      {
        id: 'Heading2',
        name: 'Heading 2',
        basedOn: 'Normal',
        next: 'Normal',
        quickFormat: true,
        run: { font: 'Arial', size: 28, bold: true, color: '1F3864' },
        paragraph: {
          spacing: { before: 300, after: 120 },
          outlineLevel: 1,
          border: {
            bottom: { style: BorderStyle.SINGLE, size: 6, color: '1F3864', space: 1 }
          }
        }
      },
      {
        id: 'Heading3',
        name: 'Heading 3',
        basedOn: 'Normal',
        next: 'Normal',
        quickFormat: true,
        run: { font: 'Arial', size: 24, bold: true, color: '2E5F8A' },
        paragraph: {
          spacing: { before: 240, after: 80 },
          outlineLevel: 2
        }
      },
      {
        id: 'Heading4',
        name: 'Heading 4',
        basedOn: 'Normal',
        next: 'Normal',
        quickFormat: true,
        run: { font: 'Arial', size: 22, bold: true, italic: true, color: '444444' },
        paragraph: {
          spacing: { before: 180, after: 60 },
          outlineLevel: 3
        }
      },
      {
        id: 'BlockText',
        name: 'Block Text',
        basedOn: 'Normal',
        run: { font: 'Times New Roman', size: 22, italic: true },
        paragraph: {
          indent: { left: 720 },
          spacing: { before: 80, after: 80 }
        }
      },
      {
        id: 'SourceCode',
        name: 'Source Code',
        basedOn: 'Normal',
        run: { font: 'Courier New', size: 20, color: '333333' },
        paragraph: {
          spacing: { before: 80, after: 80 },
          shading: { fill: 'F5F5F5' }
        }
      },
      {
        id: 'VerbatimChar',
        name: 'Verbatim Char',
        basedOn: 'Normal',
        run: { font: 'Courier New', size: 20 }
      }
    ]
  },

  numbering: {
    config: [
      {
        reference: 'bullets',
        levels: [{
          level: 0, format: LevelFormat.BULLET, text: '•',
          alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } } }
        }, {
          level: 1, format: LevelFormat.BULLET, text: '◦',
          alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 1080, hanging: 360 } } }
        }]
      },
      {
        reference: 'numbers',
        levels: [{
          level: 0, format: LevelFormat.DECIMAL, text: '%1.',
          alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } } }
        }]
      }
    ]
  },

  sections: [{
    properties: {
      page: {
        size: { width: 11906, height: 16838 },  // A4 en DXA
        margin: {
          top:    Math.round(2.5 * CM),
          bottom: Math.round(2.5 * CM),
          left:   Math.round(2.5 * CM),
          right:  Math.round(2.5 * CM),
          header: Math.round(1.0 * CM),
          footer: Math.round(1.0 * CM)
        }
      }
    },
    footers: {
      default: new Footer({
        children: [new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [
            new TextRun({ children: [PageNumber.CURRENT], font: 'Arial', size: 18, color: '666666' }),
            new TextRun({ text: ' / ', font: 'Arial', size: 18, color: '666666' }),
            new TextRun({ children: [PageNumber.TOTAL_PAGES], font: 'Arial', size: 18, color: '666666' })
          ]
        })]
      })
    },
    children: [
      new Paragraph({ children: [new TextRun('Document de référence — styles pandoc')] })
    ]
  }]
});

Packer.toBuffer(doc).then(buf => {
  fs.writeFileSync('reference.docx', buf);
  console.log('reference.docx créé.');
});
