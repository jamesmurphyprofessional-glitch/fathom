#pragma once

#include "fathom/workbench.hpp"

#include <QGraphicsView>

#include <vector>

namespace fathom {

class GraphView : public QGraphicsView {
    Q_OBJECT

public:
    explicit GraphView(QWidget* parent = nullptr);

    void set_blocks(const std::vector<GraphBlock>& blocks, uint64_t cursor);
    void set_cursor(uint64_t cursor);

signals:
    void addressChosen(quint64 address);

protected:
    void wheelEvent(QWheelEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;

private:
    class BlockItem;

    void rebuild();
    bool block_is_hot(uint64_t start) const;

    std::vector<GraphBlock> blocks_;
    uint64_t cursor_ = 0;
    bool panning_ = false;
    QPoint pan_origin_;
    double zoom_ = 1.0;
};

}  // namespace fathom
