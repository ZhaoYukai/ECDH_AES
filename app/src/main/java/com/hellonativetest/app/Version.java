package com.hellonativetest.app;

/**
 * MagicCrypt的版本。
 *
 * @author Magic Len
 */
public final class Version {

    /**
     * 主版本號碼。當程式架構有了重大改變，將會調整這項數值。
     */
    public static final int MAJOR = 1;
    /**
     * 副版本號碼。當程式新增了功能，將會調整這項數值。
     */
    public static final int MINOR = 1;
    /**
     * 維護版本號碼。當程式優化或是修正了一些問題，將會調整這項數值。
     */
    public static final int MAINTENANCE = 0;

    /**
     * 私有的建構子，將無法被實體化。
     */
    private Version() {

    }

    /**
     * 取得版本字串。
     *
     * @return 傳回版本字串
     */
    public static String getVersion() {
	return String.format("%d.%d.%d", MAJOR, MINOR, MAINTENANCE);
    }
}
