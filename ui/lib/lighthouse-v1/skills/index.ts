import type { Skill, SkillMetadata } from "./types";

const SKILLS: Skill[] = [];

export function getAllSkillMetadata(): SkillMetadata[] {
  return SKILLS.map((skill) => skill.metadata);
}

export function getRegisteredSkillIds(): string[] {
  return SKILLS.map((skill) => skill.metadata.id);
}

export function getSkillById(id: string): Skill | undefined {
  return SKILLS.find((skill) => skill.metadata.id === id);
}
