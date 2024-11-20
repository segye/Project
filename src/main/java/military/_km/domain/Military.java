package military._km.domain;

public enum Military {
    army("육군"), marine("해병대"), navy("해군"), air_force("공군");

    private String value;

    Military(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static Military fromValue(String value) {
        for (Military military : Military.values()) {
            if (military.getValue().equals(value)) {
                return military;
            }
        }
        throw new IllegalArgumentException("알수없는 Value " + value);
    }
}
