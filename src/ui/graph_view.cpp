#include "graph_view.hpp"

#include "fathom/util.hpp"
#include "theme.hpp"

#include <QGraphicsItem>
#include <QGraphicsScene>
#include <QGraphicsTextItem>
#include <QMouseEvent>
#include <QPainter>
#include <QScrollBar>
#include <QTimer>
#include <QPainterPath>
#include <QWheelEvent>

#include <algorithm>
#include <unordered_map>

namespace fathom {
namespace {

constexpr int kWidth = 280;
constexpr int kPad = 10;
constexpr int kTitle = 18;
constexpr int kLine = 16;

}  // namespace

class GraphView::BlockItem : public QGraphicsItem {
public:
    BlockItem(GraphBlock block, bool hot) : block_(std::move(block)), hot_(hot) {
        setData(0, static_cast<qulonglong>(block_.start));
    }

    void set_hot(bool hot) {
        hot_ = hot;
        update();
    }

    QRectF boundingRect() const override {
        const int lines = static_cast<int>(std::max<size_t>(block_.lines.size(), 1));
        return QRectF(0, 0, kWidth, kPad + kTitle + lines * kLine + kPad);
    }

    void paint(QPainter* painter, const QStyleOptionGraphicsItem*, QWidget*) override {
        painter->setRenderHint(QPainter::TextAntialiasing, true);
        const QRectF box = boundingRect().adjusted(0.5, 0.5, -0.5, -0.5);
        painter->setPen(QPen(hot_ ? theme::kCopper : theme::kLine, hot_ ? 1.6 : 1.0));
        painter->setBrush(hot_ ? theme::kBlockHot : theme::kBlock);
        painter->drawRoundedRect(box, 4, 4);
        painter->setFont(theme::code_font(11));
        painter->setPen(theme::kAddress);
        painter->drawText(QRectF(kPad, kPad, kWidth - 2 * kPad, kTitle), Qt::AlignLeft | Qt::AlignVCenter,
                          QString::fromStdString(hex_addr(block_.start)));
        painter->setPen(theme::kInk);
        for (size_t i = 0; i < block_.lines.size(); ++i) {
            painter->drawText(QRectF(kPad, kPad + kTitle + static_cast<int>(i) * kLine, kWidth - 2 * kPad, kLine),
                              Qt::AlignLeft | Qt::AlignVCenter, QString::fromStdString(block_.lines[i]));
        }
    }

private:
    GraphBlock block_;
    bool hot_ = false;
};

GraphView::GraphView(QWidget* parent) : QGraphicsView(parent) {
    setScene(new QGraphicsScene(this));
    setRenderHint(QPainter::Antialiasing, true);
    setBackgroundBrush(theme::kField);
    setFrameShape(QFrame::NoFrame);
    setTransformationAnchor(QGraphicsView::AnchorUnderMouse);
    setDragMode(QGraphicsView::NoDrag);
}

void GraphView::set_blocks(const std::vector<GraphBlock>& blocks, uint64_t cursor) {
    blocks_ = blocks;
    cursor_ = cursor;
    zoom_ = 1.0;
    resetTransform();
    rebuild();
}

void GraphView::set_cursor(uint64_t cursor) {
    cursor_ = cursor;
    const auto items = scene()->items();
    for (QGraphicsItem* item : items) {
        auto* block = dynamic_cast<BlockItem*>(item);
        if (block == nullptr) {
            continue;
        }
        block->set_hot(block_is_hot(static_cast<uint64_t>(block->data(0).toULongLong())));
    }
}

bool GraphView::block_is_hot(uint64_t start) const {
    uint64_t best = 0;
    bool any = false;
    for (const auto& block : blocks_) {
        if (block.start <= cursor_ && (!any || block.start >= best)) {
            best = block.start;
            any = true;
        }
    }
    return any && best == start;
}

void GraphView::rebuild() {
    scene()->clear();
    if (blocks_.empty()) {
        auto* text = scene()->addText(QStringLiteral("No function at the cursor"));
        text->setDefaultTextColor(theme::kMuted);
        text->setFont(theme::code_font());
        scene()->setSceneRect(text->boundingRect().adjusted(-24, -24, 24, 24));
        return;
    }

    std::unordered_map<uint64_t, BlockItem*> nodes;
    qreal y = 24;
    for (const auto& block : blocks_) {
        auto* item = new BlockItem(block, block_is_hot(block.start));
        item->setPos(48, y);
        scene()->addItem(item);
        nodes.emplace(block.start, item);
        y += item->boundingRect().height() + 36;
    }

    for (const auto& block : blocks_) {
        BlockItem* from = nodes[block.start];
        const QPointF start(from->pos().x() + from->boundingRect().width() / 2,
                            from->pos().y() + from->boundingRect().height());
        for (uint64_t succ : block.succs) {
            const auto it = nodes.find(succ);
            if (it == nodes.end()) {
                continue;
            }
            BlockItem* to = it->second;
            const QPointF end(to->pos().x() + to->boundingRect().width() / 2, to->pos().y());
            QPainterPath path(start);
            const qreal mid = (start.y() + end.y()) / 2;
            if (end.y() > start.y()) {
                path.cubicTo(QPointF(start.x(), mid), QPointF(end.x(), mid), end);
            } else {
                const qreal side = std::max(start.x(), end.x()) + 48;
                path.cubicTo(QPointF(side, start.y()), QPointF(side, end.y()), end);
            }
            auto* edge = scene()->addPath(path, QPen(theme::kEdge, 1.3));
            edge->setAcceptedMouseButtons(Qt::NoButton);
            edge->setZValue(-1);
        }
    }

    scene()->setSceneRect(scene()->itemsBoundingRect().adjusted(-32, -32, 80, 32));
    QTimer::singleShot(0, this, [this] {
        if (blocks_.empty() || scene() == nullptr) {
            return;
        }
        const QRectF bounds = scene()->itemsBoundingRect();
        const double target = bounds.width() > 1 ? 460.0 / bounds.width() : 1.0;
        const double factor = std::clamp(target, 0.85, 1.35);
        zoom_ = factor;
        resetTransform();
        scale(factor, factor);
        centerOn(bounds.center());
    });
}

void GraphView::wheelEvent(QWheelEvent* event) {
    const double step = event->angleDelta().y() > 0 ? 1.12 : 1.0 / 1.12;
    const double next = std::clamp(zoom_ * step, 0.35, 2.8);
    if (next == zoom_) {
        event->accept();
        return;
    }
    const double applied = next / zoom_;
    zoom_ = next;
    scale(applied, applied);
    event->accept();
}

void GraphView::mousePressEvent(QMouseEvent* event) {
    QGraphicsItem* item = itemAt(event->pos());
    if (item != nullptr && item->data(0).isValid() && event->button() == Qt::LeftButton) {
        emit addressChosen(item->data(0).toULongLong());
        event->accept();
        return;
    }
    if (event->button() == Qt::LeftButton) {
        panning_ = true;
        pan_origin_ = event->pos();
        setCursor(Qt::ClosedHandCursor);
        event->accept();
        return;
    }
    QGraphicsView::mousePressEvent(event);
}

void GraphView::mouseMoveEvent(QMouseEvent* event) {
    if (!panning_) {
        QGraphicsView::mouseMoveEvent(event);
        return;
    }
    const QPoint delta = event->pos() - pan_origin_;
    pan_origin_ = event->pos();
    horizontalScrollBar()->setValue(horizontalScrollBar()->value() - delta.x());
    verticalScrollBar()->setValue(verticalScrollBar()->value() - delta.y());
    event->accept();
}

void GraphView::mouseReleaseEvent(QMouseEvent* event) {
    if (panning_ && event->button() == Qt::LeftButton) {
        panning_ = false;
        unsetCursor();
        event->accept();
        return;
    }
    QGraphicsView::mouseReleaseEvent(event);
}

}  // namespace fathom
