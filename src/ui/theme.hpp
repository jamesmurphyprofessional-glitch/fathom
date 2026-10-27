#pragma once

#include <QColor>
#include <QFont>
#include <QFontInfo>

namespace fathom::theme {

inline const QColor kAddress(0x7e, 0xb6, 0xd6);
inline const QColor kMnemonic(0xe4, 0xc4, 0x8a);
inline const QColor kOperand(0xd5, 0xdd, 0xe6);
inline const QColor kMuted(0x8e, 0xa0, 0xb5);
inline const QColor kInk(0xd5, 0xdd, 0xe6);
inline const QColor kCopper(0xd0, 0x8a, 0x4c);
inline const QColor kPanel(0x1a, 0x23, 0x30);
inline const QColor kField(0x12, 0x18, 0x1f);
inline const QColor kBlock(0x22, 0x30, 0x44);
inline const QColor kBlockHot(0x3a, 0x2e, 0x24);
inline const QColor kLine(0x2c, 0x3b, 0x4d);
inline const QColor kEdge(0x6d, 0x82, 0x96);

inline QFont code_font(int points = 12) {
    QFont font(QStringLiteral("Menlo"));
    font.setStyleHint(QFont::Monospace);
    font.setPointSize(points);
    if (!QFontInfo(font).family().contains(QStringLiteral("Menlo"), Qt::CaseInsensitive)) {
        font.setFamily(QStringLiteral("Monaco"));
    }
    return font;
}

inline constexpr char kStyle[] = R"(
QMainWindow, QWidget {
    background: #12181f;
    color: #d5dde6;
}
QLineEdit, QPlainTextEdit, QListWidget, QTableView, QGraphicsView {
    background: #1a2330;
    color: #d5dde6;
    border: 1px solid #2c3b4d;
    selection-background-color: #3d3428;
    selection-color: #f4ecdf;
}
QHeaderView::section {
    background: #16202b;
    color: #8ea0b5;
    border: none;
    padding: 4px 8px;
}
QMenuBar {
    background: #0e141b;
    color: #d5dde6;
}
QMenuBar::item:selected, QMenu::item:selected {
    background: #3d3428;
}
QMenu {
    background: #1a2330;
    color: #d5dde6;
    border: 1px solid #2c3b4d;
}
QStatusBar {
    background: #0e141b;
    color: #8ea0b5;
}
QSplitter::handle {
    background: #0e141b;
}
QScrollBar:vertical {
    background: #12181f;
    width: 12px;
    margin: 0;
}
QScrollBar:horizontal {
    background: #12181f;
    height: 12px;
    margin: 0;
}
QScrollBar::handle:vertical, QScrollBar::handle:horizontal {
    background: #2c3b4d;
    min-height: 24px;
    min-width: 24px;
}
QScrollBar::add-line, QScrollBar::sub-line {
    height: 0;
    width: 0;
}
)";

}  // namespace fathom::theme
