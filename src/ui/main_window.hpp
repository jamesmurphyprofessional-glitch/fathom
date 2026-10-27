#pragma once

#include "fathom/workbench.hpp"

#include <QMainWindow>

#include <optional>

class QAction;
class QLabel;
class QLineEdit;
class QListWidget;
class QPlainTextEdit;
class QSplitter;
class QStackedWidget;
class QTableView;

namespace fathom {

class DisasmModel;
class GraphView;
class HexModel;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);

    void open_path(const QString& path);

protected:
    void dragEnterEvent(QDragEnterEvent* event) override;
    void dropEvent(QDropEvent* event) override;
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    struct LoadResult {
        Program program;
        std::string error;
    };

    void build_ui();
    void open_dialog();
    void go_to_address();
    void set_lower(LowerView view);
    void choose(uint64_t address);
    void refresh_lists();
    void refresh_xrefs();
    void refresh_views(bool function_changed);
    void refresh_status();
    void fill_list(QListWidget* list, const std::vector<std::pair<uint64_t, QString>>& rows, int cap);
    std::optional<uint64_t> shown_function() const;

    Workbench bench_;
    int ticket_ = 0;
    bool updating_ = false;
    std::optional<uint64_t> shown_function_;

    QLineEdit* filter_ = nullptr;
    QListWidget* functions_ = nullptr;
    QListWidget* strings_ = nullptr;
    QListWidget* triage_ = nullptr;
    QListWidget* xrefs_ = nullptr;
    QTableView* disasm_ = nullptr;
    DisasmModel* disasm_model_ = nullptr;
    QPlainTextEdit* listing_ = nullptr;
    QTableView* hex_ = nullptr;
    HexModel* hex_model_ = nullptr;
    GraphView* graph_ = nullptr;
    QStackedWidget* lower_ = nullptr;
    QAction* hex_action_ = nullptr;
    QAction* graph_action_ = nullptr;
    QLabel* status_arch_ = nullptr;
    QLabel* status_cursor_ = nullptr;
    QLabel* status_path_ = nullptr;
};

}  // namespace fathom
