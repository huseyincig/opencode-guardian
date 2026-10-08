import type { GuardianToastPayload } from "./toast.js";
export declare const GUARDIAN_INTERVENTION_RPC_ID = "opencode-guardian.intervention";
export declare const GUARDIAN_INTERVENTION_RPC_METHOD = "latest";
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
