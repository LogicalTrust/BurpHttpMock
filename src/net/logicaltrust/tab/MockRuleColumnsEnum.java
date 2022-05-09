package net.logicaltrust.tab;

import net.logicaltrust.model.MockProtocolEnum;

import java.util.Arrays;

public enum MockRuleColumnsEnum {

    ENABLED("Enabled"),

    PROTOCOL("Protocol"),

    HOST("Host"),

    PORT("Port"),

    METHOD("Method"),
    PATH("File");

    private final String displayName;

    MockRuleColumnsEnum(String displayName) {
        this.displayName = displayName;
    }

    public static Object[] getDisplayNames() {
        return Arrays.stream(MockRuleColumnsEnum.values()).map(v -> v.displayName).toArray();
    }

    public static MockRuleColumnsEnum getByIndex(int index) {
        return MockRuleColumnsEnum.values()[index];
    }

    public static Class<?> getType(int index) {
        if (index == 0) {
            return Boolean.class;
        } else if (index == 1) {
            return MockProtocolEnum.class;
        }
        return String.class;
    }


}
