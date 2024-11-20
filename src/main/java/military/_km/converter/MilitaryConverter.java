package military._km.converter;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import military._km.domain.Military;

@Converter(autoApply = true)
public class MilitaryConverter implements AttributeConverter<Military, String> {

    @Override
    public String convertToDatabaseColumn(Military attribute) {
        return attribute != null ? attribute.getValue() : null;
    }

    @Override
    public Military convertToEntityAttribute(String dbData) {
        return dbData != null ? Military.fromValue(dbData) : null;
    }
}
