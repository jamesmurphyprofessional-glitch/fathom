#include "disasm_model.hpp"

#include "fathom/util.hpp"
#include "theme.hpp"

#include <QColor>

namespace fathom {

DisasmModel::DisasmModel(QObject* parent) : QAbstractTableModel(parent) {}

void DisasmModel::set_rows(std::vector<DisasmRow> rows) {
    beginResetModel();
    rows_ = std::move(rows);
    endResetModel();
}

uint64_t DisasmModel::address_at(int row) const {
    if (row < 0 || static_cast<size_t>(row) >= rows_.size()) {
        return 0;
    }
    return rows_[static_cast<size_t>(row)].address;
}

int DisasmModel::row_for(uint64_t address) const {
    for (size_t i = 0; i < rows_.size(); ++i) {
        if (rows_[i].address == address) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

int DisasmModel::rowCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : static_cast<int>(rows_.size());
}

int DisasmModel::columnCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : 3;
}

QVariant DisasmModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || static_cast<size_t>(index.row()) >= rows_.size()) {
        return {};
    }
    const DisasmRow& row = rows_[static_cast<size_t>(index.row())];
    if (role == Qt::FontRole) {
        return theme::code_font();
    }
    if (role == Qt::ForegroundRole) {
        if (index.column() == 0) {
            return theme::kAddress;
        }
        if (index.column() == 1) {
            return theme::kMuted;
        }
        if (row.call || row.jump) {
            return theme::kMnemonic;
        }
        if (row.ret) {
            return theme::kCopper;
        }
        return theme::kOperand;
    }
    if (role != Qt::DisplayRole) {
        return {};
    }
    switch (index.column()) {
    case 0:
        return QString::fromStdString(hex_addr(row.address));
    case 1:
        return QString::fromStdString(row.bytes);
    case 2: {
        QString text = QString::fromStdString(row.mnemonic);
        if (!row.operands.empty()) {
            text += QLatin1Char(' ');
            text += QString::fromStdString(row.operands);
        }
        return text;
    }
    default:
        return {};
    }
}

QVariant DisasmModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return {};
    }
    switch (section) {
    case 0:
        return QStringLiteral("Address");
    case 1:
        return QStringLiteral("Bytes");
    case 2:
        return QStringLiteral("Instruction");
    default:
        return {};
    }
}

}  // namespace fathom
