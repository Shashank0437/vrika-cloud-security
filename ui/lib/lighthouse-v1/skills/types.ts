export interface SkillMetadata {
  id: string;
  name: string;
  description?: string;
}

export interface Skill {
  metadata: SkillMetadata;
  instructions: string;
}
