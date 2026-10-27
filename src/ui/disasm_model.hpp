#pragma once

#include "fathom/workbench.hpp"

#include <QAbstractTableModel>

#include <vector>

namespace fathom {

class DisasmModel : public QAbstractTableModel {
public:
    explicit DisasmModel(QObject* parent = nullptr);

    void set_rows(std::vector<DisasmRow> rows);
    uint64_t address_at(int row) const;
    int row_for(uint64_t address) const;

    int rowCount(const QModelIndex& parent = {}) const override;
    int columnCount(const QModelIndex& parent = {}) const override;
    QVariant data(const QModelIndex& index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

private:
    std::vector<DisasmRow> rows_;
};

}  // namespace fathom
