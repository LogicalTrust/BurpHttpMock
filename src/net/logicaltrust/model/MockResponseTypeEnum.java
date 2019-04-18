package net.logicaltrust.model;

public enum MockResponseTypeEnum {
    DirectEntry { //traditional one, just returns whatever was entered by the user in the text box
        @Override
        public byte[] generateResponse(byte[] ruleInput) {
            return ruleInput;
        }
    },
    FileInclusion {
        @Override
        public byte[] generateResponse(byte[] ruleInput) {
            throw new UnsupportedOperationException();
        }
    },
    CgiScript {
        @Override
        public byte[] generateResponse(byte[] ruleInput) {
            throw new UnsupportedOperationException();
        }
    },
    UrlRedirect {
        @Override
        public byte[] generateResponse(byte[] ruleInput) {
            throw new UnsupportedOperationException();
        }
    };

    public abstract byte[] generateResponse(byte[] ruleInput);
}
