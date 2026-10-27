#include "hex_model.hpp"

#include "fathom/util.hpp"
#include "theme.hpp"

namespace fathom {

HexModel::HexModel(QObject* parent) : QAbstractTableModel(parent) {}

void HexModel::set_lines(std::vector<HexLine> lines) {
    beginResetModel();
    lines_ = std::move(lines);
    endResetModel();
}

std::optional<uint64_t> HexModel::address_at(const QModelIndex& index) const {
    if (!index.isValid() || static_cast<size_t>(index.row()) >= lines_.size()) {
        return std::nullopt;
    }
    const HexLine& line = lines_[static_cast<size_t>(index.row())];
    if (index.column() == 0) {
        return line.address;
    }
    if (index.column() >= 1 && index.column() <= 16) {
        const HexCell& cell = line.cells[static_cast<size_t>(index.column() - 1)];
        if (!cell.present) {
            return std::nullopt;
        }
        return cell.address;
    }
    return std::nullopt;
}

QModelIndex HexModel::index_for(uint64_t address) const {
    for (size_t row = 0; row < lines_.size(); ++row) {
        const HexLine& line = lines_[row];
        for (size_t col = 0; col < line.cells.size(); ++col) {
            if (line.cells[col].present && line.cells[col].address == address) {
                return index(static_cast<int>(row), static_cast<int>(col + 1));
            }
        }
    }
    return {};
}

int HexModel::rowCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : static_cast<int>(lines_.size());
}

int HexModel::columnCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : 18;
}

QVariant HexModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || static_cast<size_t>(index.row()) >= lines_.size()) {
        return {};
    }
    const HexLine& line = lines_[static_cast<size_t>(index.row())];
    if (role == Qt::FontRole) {
        return theme::code_font();
    }
    if (role == Qt::TextAlignmentRole) {
        return static_cast<int>(Qt::AlignCenter);
    }
    if (role == Qt::ForegroundRole) {
        return index.column() == 0 ? theme::kAddress : theme::kOperand;
    }
    if (role != Qt::DisplayRole) {
        return {};
    }
    if (index.column() == 0) {
        return QString::fromStdString(hex_addr(line.address));
    }
    if (index.column() == 17) {
        return QString::fromStdString(line.ascii);
    }
    if (index.column() >= 1 && index.column() <= 16) {
        const HexCell& cell = line.cells[static_cast<size_t>(index.column() - 1)];
        if (!cell.present) {
            return QString();
        }
        return QStringLiteral("%1").arg(cell.value, 2, 16, QLatin1Char('0'));
    }
    return {};
}

QVariant HexModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return {};
    }
    if (section == 0) {
        return QStringLiteral("Address");
    }
    if (section == 17) {
        return QStringLiteral("Text");
    }
    if (section >= 1 && section <= 16) {
        return QStringLiteral("%1").arg(section - 1, 0, 16).toUpper();
    }
    return {};
}

}  // namespace fathom
