import type { GuardianToastPayload } from "./toast.js";
export declare const GUARDIAN_INTERVENTION_RPC_ID = "opencode-guardian.intervention";
export declare const GUARDIAN_INTERVENTION_RPC_METHOD = "latest";
export declare const GUARDIAN_INTERVENTION_CLEAR_RPC_METHOD = "clear";
export declare const GUARDIAN_STATUS_RPC_METHOD = "status";
export declare const GUARDIAN_RESET_RPC_METHOD = "reset";
export declare const GUARDIAN_INTERVENTION_RPC_DEFINITION: {
    readonly id: "opencode-guardian.intervention";
    readonly methods: {
        readonly latest: {
            readonly input: {
                readonly type: "object";
                readonly properties: {
                    readonly sessionID: {
                        readonly type: "string";
                        readonly minLength: 1;
                        readonly maxLength: 256;
                    };
                };
                readonly required: readonly ["sessionID"];
                readonly additionalProperties: false;
            };
            readonly output: {
                readonly type: "object";
                readonly properties: {
                    readonly active: {
                        readonly type: "boolean";
                    };
                    readonly title: {
                        readonly type: "string";
                    };
                    readonly message: {
                        readonly type: "string";
                    };
                    readonly variant: {
                        readonly type: "string";
                        readonly enum: readonly ["error", "warning", "info"];
                    };
                    readonly duration: {
                        readonly type: "number";
                    };
                };
                readonly required: readonly ["active", "title", "message", "variant", "duration"];
                readonly additionalProperties: false;
            };
        };
        readonly clear: {
            readonly input: {
                readonly type: "object";
                readonly properties: {
                    readonly sessionID: {
                        readonly type: "string";
                        readonly minLength: 1;
                        readonly maxLength: 256;
                    };
                    readonly directory: {
                        readonly type: "string";
                        readonly minLength: 1;
                        readonly maxLength: 4096;
                    };
                };
                readonly additionalProperties: false;
            };
            readonly output: {
                readonly type: "object";
                readonly properties: {
                    readonly cleared: {
                        readonly type: "boolean";
                    };
                };
                readonly required: readonly ["cleared"];
                readonly additionalProperties: false;
            };
        };
        readonly status: {
            readonly input: {
                readonly type: "object";
                readonly properties: {
                    readonly directory: {
                        readonly type: "string";
                        readonly minLength: 1;
                        readonly maxLength: 4096;
                    };
                };
                readonly additionalProperties: false;
            };
            readonly output: {
                readonly type: "object";
                readonly properties: {
                    readonly ok: {
                        readonly type: "boolean";
                    };
                    readonly status: {
                        readonly type: "object";
                    };
                };
                readonly required: readonly ["ok"];
                readonly additionalProperties: false;
            };
        };
        readonly reset: {
            readonly input: {
                readonly type: "object";
                readonly properties: {
                    readonly directory: {
                        readonly type: "string";
                        readonly minLength: 1;
                        readonly maxLength: 4096;
                    };
                };
                readonly additionalProperties: false;
            };
            readonly output: {
                readonly type: "object";
                readonly properties: {
                    readonly ok: {
                        readonly type: "boolean";
                    };
                    readonly title: {
                        readonly type: "string";
                    };
                    readonly message: {
                        readonly type: "string";
                    };
                };
                readonly required: readonly ["ok", "title", "message"];
                readonly additionalProperties: false;
            };
        };
    };
    readonly events: {};
};
export interface GuardianInterventionSnapshot extends GuardianToastPayload {
    active: boolean;
}
export declare function inactiveGuardianIntervention(): GuardianInterventionSnapshot;
export declare function activeGuardianIntervention(payload: GuardianToastPayload): GuardianInterventionSnapshot;
export declare function parseGuardianInterventionSnapshot(value: unknown): GuardianInterventionSnapshot | undefined;
export declare function readGuardianInterventionSessionID(input: unknown): string | undefined;
export declare function readGuardianInterventionDirectory(input: unknown): string | undefined;
