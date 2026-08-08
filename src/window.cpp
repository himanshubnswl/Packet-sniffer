#include "window.hpp"

QStandardItemModel* Window::initializecheckbox(QObject* parent) {
    auto* model = new QStandardItemModel(parent);
    model->appendRow(makeitem(QString{"mac src"}));
    model->appendRow(makeitem(QString{"mac dest"}));
    model->appendRow(makeitem(QString{"internet type"}));
    model->appendRow(makeitem(QString{"protocol"}));
    model->appendRow(makeitem(QString{"ipv4 src"}));
    model->appendRow(makeitem(QString{"ipv4 dest"}));
    return model;
}

QStringList Window::returncheckeditems(QStandardItemModel* model) {
    QStringList item_checked;

    for (int i {0}; i < model->rowCount(); i++) {
        auto* item = model->item(i);
        if (item->data(Qt::CheckStateRole) == Qt::Checked) {
            item_checked.append(item->text());
        }
    }
}

inline QStandardItem* Window::makeitem(const QString& text) {
    auto* newitem = new QStandardItem(text);
    newitem->setFlags(Qt::ItemIsUserCheckable | Qt::ItemIsEnabled);
    newitem->setData(Qt::Checked, Qt::CheckStateRole);

    return newitem;
}


Window::Window(QWidget* parent) {
    auto* model = new MyModel(this);
    auto* layout = new QVBoxLayout(this);
    auto* view = new QTableView(this);

    auto example = model->give_example();

    QComboBox* box = new QComboBox(this);
    auto* model_for_box = initializecheckbox(this);
    box->setModel(model_for_box);
    model->add_packet(example);
    layout->addWidget(box);
    layout->addWidget(view);

    view->setModel(model);
    view->verticalHeader()->hide();
    resize(800,800);
}