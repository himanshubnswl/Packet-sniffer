//
// Created by lhbdawn on 02-08-2026.
//

#pragma once
#include <QWidget>
#include "mymodel.hpp"
#include <QTableView>
#include <QBoxLayout>
#include <QHeaderView>
#include <QComboBox>
#include <QCheckBox>
#include <QStandardItemModel>
#include <QStandardItem>
#include <QStringList>

//custom combobox which has checkboxes to implement selection of visible info
class CheckboxModel final : public QComboBox {
    Q_OBJECT

private:
    QStandardItemModel *model_box;

    inline QStandardItem *makeitem(const QString &text, int id);

signals:
    void itemchangedmodel(const QStandardItem* item);

public:
    explicit CheckboxModel(QWidget *parent = nullptr);

    QStringList returncheckeditems(QStandardItemModel *model);
};


//new class, subclasses QWidget and handles main operations of the window
class Window : public QWidget {
    Q_OBJECT

private:
    QTableView *view;

public:
    MyModel* model;
    explicit Window(QWidget *parent = nullptr);

private slots:
    void onitemchange(const QStandardItem *item);
};
