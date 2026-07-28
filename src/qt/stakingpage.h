// Copyright (c) 2026 The RuxCrypto Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_STAKINGPAGE_H
#define BITCOIN_QT_STAKINGPAGE_H

#include <QWidget>

class WalletModel;
class PlatformStyle;

QT_BEGIN_NAMESPACE
class QTimer;
QT_END_NAMESPACE

namespace Ui {
    class StakingPage;
}

/**
 * The staking tab.
 *
 * The Overview panel answers "is it staking"; this answers "why", which is the
 * question that actually comes up. A staker whose weight is zero wants to know
 * which coins are in and which are sitting out, and no summary figure tells them
 * that -- hence the table of participating outputs.
 */
class StakingPage : public QWidget
{
    Q_OBJECT

public:
    explicit StakingPage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~StakingPage();

    void setWalletModel(WalletModel *walletModel);

public Q_SLOTS:
    void updateStakingStatus();
    void toggleStaking();

private:
    Ui::StakingPage *ui;
    WalletModel *walletModel;
    QTimer *timer;
};

#endif // BITCOIN_QT_STAKINGPAGE_H
